package ge2ee

import (
	"net/http"
	"strings"

	ch "ge2ee"

	"github.com/go-chi/chi/v5"
)

func main() {
	r1 := chi.NewRouter()
	r1.Handle("/", ch.Ge2eeHandle(testhandler))
	http.ListenAndServe(":1321", r1)
	req, err := http.NewRequest("POST", "localhost:1321", strings.NewReader("goofy"))

}

func testhandler(w http.ResponseWriter, r *http.Request) {
	e, _ := ch.EncryptBody(w, r, []byte("testhandled"))
	w.Write(e)
}
