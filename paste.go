package main

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	_ "modernc.org/sqlite"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	CodeRandoms      = "abcdefghijklmnopqrstuvwxyz0123456789"
	AllowedCodeChars = CodeRandoms
	MaxCodeLength    = 64
	MaxContentLength = 4 * 1024 * 1024
)

type Paste struct {
	ID             int64  `json:"id"`
	Code           string `json:"code"`
	Content        string `json:"content"`
	ContentType    string `json:"contentType"`
	Views          int    `json:"views"`
	RemainingViews int    `json:"remainingViews"`
	Password       string `json:"password,omitempty"`
	ExpiredAt      int64  `json:"expiredAt"`
	CreatedAt      int64  `json:"createdAt"`
	CreatedBy      string `json:"createdBy,omitempty"`
	Deleted        bool   `json:"-"`
}

type Paster struct {
	db              *sql.DB
	codeLen         uint
	allowCustomCode bool
}

func NewPaster(db *sql.DB, codeLen uint, allowCustomCode bool) *Paster {
	if codeLen < 4 {
		panic("code length cannot less than 4")
	}
	return &Paster{db: db, codeLen: codeLen, allowCustomCode: allowCustomCode}
}

func (p *Paster) Add(paste Paste) (Paste, error) {
	if (paste.Code != "" && !p.allowCustomCode) ||
		len(paste.Code) > MaxCodeLength ||
		paste.Content == "" ||
		len(paste.ContentType) > 16 ||
		len(paste.Content) > MaxContentLength {
		return Paste{}, NewPasteOpError(400, "")
	}
	if paste.Code != "" {
		for _, c := range paste.Code {
			if strings.IndexRune(AllowedCodeChars, c) < 0 {
				return Paste{}, NewPasteOpError(400, "invalid code")
			}
		}
		exists, e := p.exists(paste.Code)
		if e != nil {
			return Paste{}, e
		}
		if exists {
			return Paste{}, NewPasteOpError(409, "code exists")
		}
	} else {
		tries := 8
		for {
			if tries == 0 {
				return Paste{}, errors.New("failed to generate unique code")
			}
			tries--
			paste.Code = p.generateCode()
			exists, e := p.exists(paste.Code)
			if e != nil {
				return Paste{}, e
			}
			if !exists {
				break
			}
		}
	}

	encodedPassword := ""
	if paste.Password != "" {
		b, e := bcrypt.GenerateFromPassword([]byte(paste.Password), bcrypt.DefaultCost)
		if e != nil {
			return Paste{}, e
		}
		encodedPassword = string(b)
	}

	paste.ID = 0
	if paste.RemainingViews <= 0 {
		paste.RemainingViews = -1
	}
	paste.CreatedAt = time.Now().UnixMilli()
	if paste.ExpiredAt < paste.CreatedAt {
		paste.ExpiredAt = -1
	}
	paste.Views = 0
	paste.Deleted = false

	result, e := p.db.Exec(
		`INSERT INTO pastes(code, content, content_type, views, remaining_views, password,
                   expired_at, created_at, created_by, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		paste.Code, paste.Content, paste.ContentType, paste.Views, paste.RemainingViews, encodedPassword,
		paste.ExpiredAt, paste.CreatedAt, paste.CreatedBy, paste.Deleted,
	)
	if e != nil {
		return Paste{}, e
	}
	paste.ID, e = result.LastInsertId()
	if e != nil {
		return Paste{}, e
	}
	return paste, nil
}

func (p *Paster) Get(code, password string) (Paste, error) {
	paste, e := p.get(code)
	if e != nil {
		return Paste{}, e
	}
	if paste.Password != "" && bcrypt.CompareHashAndPassword([]byte(paste.Password), []byte(password)) != nil {
		return Paste{}, NewPasteOpError(403, "invalid password")
	}
	if e := p.checkAndConsume(&paste); e != nil {
		return Paste{}, e
	}
	return paste, nil
}

func (p *Paster) get(code string) (Paste, error) {
	var paste Paste
	if e := p.db.QueryRow(
		`SELECT id, code,content, content_type, views, remaining_views, password,
       			expired_at, created_at, created_by FROM pastes WHERE code = ? AND deleted = 0`,
		code).Scan(
		&paste.ID, &paste.Code, &paste.Content, &paste.ContentType, &paste.Views,
		&paste.RemainingViews, &paste.Password, &paste.ExpiredAt, &paste.CreatedAt, &paste.CreatedBy,
	); e != nil {
		if e == sql.ErrNoRows {
			return Paste{}, NewPasteOpError(404, "not found")
		}
		return paste, e
	}
	return paste, nil
}

func (p *Paster) checkAndConsume(paste *Paste) error {
	now := time.Now().UnixMilli()
	paste.Views++
	if paste.RemainingViews > 0 {
		paste.RemainingViews--
	}
	expired := paste.ExpiredAt >= 0 && paste.ExpiredAt < now
	if paste.RemainingViews == 0 || expired {
		if e := p.Delete(paste.Code); e != nil {
			return e
		}
		if expired {
			return NewPasteOpError(404, "not found")
		}
		return nil
	}
	if _, e := p.db.Exec(
		"UPDATE pastes SET views = views + 1, remaining_views = ? WHERE code = ?",
		paste.RemainingViews, paste.Code,
	); e != nil {
		return e
	}
	return nil
}

func (p *Paster) Delete(code string) error {
	_, e := p.db.Exec(
		`UPDATE pastes SET content = '', content_type = '', views = -1, remaining_views = -1, password = '',
                  expired_at = -1, created_at = -1, created_by = '', deleted = 1 WHERE code = ?`,
		code,
	)
	return e
}

func (p *Paster) exists(code string) (bool, error) {
	count := 0
	if e := p.db.QueryRow("SELECT COUNT(code) FROM pastes WHERE code = ?", code).Scan(&count); e != nil {
		return false, e
	}
	return count > 0, nil
}

func (p *Paster) generateCode() string {
	rand.Seed(time.Now().UnixNano())
	sb := strings.Builder{}
	for i := uint(0); i < p.codeLen; i++ {
		sb.WriteRune(rune(CodeRandoms[rand.Intn(len(CodeRandoms))]))
	}
	code := sb.String()
	return code
}

func (p *Paster) cleanup() int64 {
	result, e := p.db.Exec(
		`UPDATE pastes SET content = '', content_type = '', views = -1, remaining_views = -1, password = '',
                  expired_at = -1, created_at = -1, created_by = '', deleted = 1
			   WHERE expired_at >= 0 AND expired_at < ?`,
		time.Now().UnixMilli(),
	)
	if e != nil {
		log.Printf("failed to executing cleanup: %s\n", e.Error())
		return -1
	}
	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("%d expired pastes cleanuped\n", rows)
	}
	return rows
}

func (p *Paster) init() error {
	_, e := p.db.Exec(
		`CREATE TABLE pastes
				(
					id              INTEGER
						CONSTRAINT pastes_pk
							PRIMARY KEY AUTOINCREMENT,
					code            VARCHAR(64)  NOT NULL,
					content         TEXT,
					content_type    VARCHAR(32),
					views           INT          NOT NULL,
					remaining_views INT          NOT NULL,
					password        VARCHAR(64)  NOT NULL,
					expired_at      BIGINT       NOT NULL,
					created_at      BIGINT       NOT NULL,
					created_by      VARCHAR(256) NOT NULL,
					deleted         TINYINT
				);
	
				CREATE UNIQUE INDEX pastes_code_uindex
					ON pastes (code);`,
	)
	return e
}

type PasteHttpHandler struct {
	p *Paster
}

func (p *PasteHttpHandler) getCode(u *url.URL) string {
	code := strings.Trim(u.Path, "/")
	if code == "" {
		code = strings.TrimSpace(u.Query().Get("code"))
	}
	return code
}

func (p *PasteHttpHandler) handleGet(w http.ResponseWriter, req *http.Request) {
	code := p.getCode(req.URL)
	password := req.URL.Query().Get("p")
	if code == "" {
		_ = writeWebPage(w)
		return
	}
	paste, e := p.p.Get(code, password)
	if e != nil {
		writePasteError(w, e)
		return
	}
	_ = writePaste(w, paste, req.URL.Query().Has("json"))
}

func (p *PasteHttpHandler) handleAdd(w http.ResponseWriter, req *http.Request) {
	t, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	body, e := ioutil.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
	if e != nil {
		w.WriteHeader(500)
		return
	}

	var paste Paste
	if t == "application/json" {
		if e := json.Unmarshal(body, &paste); e != nil {
			w.WriteHeader(400)
			return
		}
	} else {
		paste.Content = string(body)
		paste.ContentType = req.URL.Query().Get("contentType")
		paste.RemainingViews = Int(req.URL.Query().Get("remainingViews"), -1)
		paste.Password = req.URL.Query().Get("password")
		paste.ExpiredAt = Int64(req.URL.Query().Get("expiredAt"), -1)
	}
	code := p.getCode(req.URL)
	if code != "" {
		paste.Code = code
	}
	paste.CreatedBy = GetRealIP(req)

	added, e := p.p.Add(paste)
	if e != nil {
		writePasteError(w, e)
		return
	}
	_ = writePaste(w, added, true)
}

func (p *PasteHttpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		p.handleGet(w, req)
	case http.MethodPost:
		p.handleAdd(w, req)
	default:
		w.WriteHeader(400)
	}
}

func init() {
	initTypeHandlers()
}

func main() {
	listen := flag.String("l", ":9803", "Listen address and port")
	dbName := flag.String("db", "./paste.db", "SQLite3 database file path")
	init := flag.Bool("init", false, "Initialize SQLite3 database")
	flag.Parse()

	db, e := sql.Open("sqlite", fmt.Sprintf("file:%s", *dbName))
	if e != nil {
		log.Fatalf("failed to open database: %s\n", e.Error())
	}

	p := NewPaster(db, 8, true)

	if *init {
		if e := p.init(); e != nil {
			log.Fatalf("error: %s\n", e.Error())
		}
		os.Exit(0)
	}

	ph := &PasteHttpHandler{p}

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		select {
		case <-ticker.C:
			p.cleanup()
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/", ph)

	log.Fatalln(http.ListenAndServe(*listen, mux))
}

func GetRealIP(r *http.Request) string {
	clientIP := r.RemoteAddr[:strings.LastIndex(r.RemoteAddr, ":")]
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return clientIP
	}
	ips := strings.Split(forwarded, ",")
	return strings.TrimSpace(ips[0])
}

type PasteOpError struct {
	status int
	msg    string
}

func NewPasteOpError(status int, msg string) PasteOpError {
	return PasteOpError{status: status, msg: msg}
}

func (r PasteOpError) Error() string {
	return r.msg
}

func (r PasteOpError) Status() int {
	return r.status
}

var pastesTypeHandlers map[string]func(w http.ResponseWriter, paste Paste) error

func initTypeHandlers() {
	pastesTypeHandlers = map[string]func(w http.ResponseWriter, paste Paste) error{
		"": func(w http.ResponseWriter, paste Paste) error {
			_, e := w.Write([]byte(paste.Content))
			return e
		},
		"url": func(w http.ResponseWriter, paste Paste) error {
			content := strings.TrimSpace(paste.Content)
			if !urlRegexp.MatchString(content) {
				return pastesTypeHandlers[""](w, paste)
			}
			w.Header().Set("Location", content)
			w.WriteHeader(302)
			return nil
		},
	}
}

func writePaste(w http.ResponseWriter, paste Paste, outputJson bool) error {
	paste.CreatedBy = ""
	paste.Password = ""

	if outputJson {
		jsonBody, e := json.Marshal(paste)
		if e != nil {
			log.Println(e)
			w.WriteHeader(500)
			return e
		}
		w.Header().Add("Content-Type", "application/json; charset=utf-8")
		_, e = w.Write(jsonBody)
		return e
	}
	handler, ok := pastesTypeHandlers[paste.ContentType]
	if !ok {
		handler = pastesTypeHandlers[""]
	}
	return handler(w, paste)
}

func writePasteError(w http.ResponseWriter, e error) {
	if ee, ok := e.(PasteOpError); ok {
		w.WriteHeader(ee.Status())
		_, _ = w.Write([]byte(ee.Error()))
		return
	}
	log.Println(e)
	w.WriteHeader(500)
}

func writeWebPage(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, e := w.Write(getHTML())
	return e
}

func Int64(s string, defVal int64) int64 {
	v, e := strconv.ParseInt(s, 10, 64)
	if e != nil {
		return defVal
	}
	return v
}

func Int(s string, defVal int) int {
	v, e := strconv.Atoi(s)
	if e != nil {
		return defVal
	}
	return v
}

func getHTML() []byte {
	stat, e := os.Stat("paste.html")
	if e != nil {
		return webPageHTMLBytes
	}
	bytes, e := ioutil.ReadFile(stat.Name())
	if e != nil {
		return webPageHTMLBytes
	}
	return bytes
}

//go:embed paste.html
var webPageHTMLBytes []byte

var urlRegexp = regexp.MustCompile("^https?://(www\\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_+.~#?&/=]*)$")
