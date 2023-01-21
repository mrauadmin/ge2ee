package main

import (
	"fmt"
	ch "ge2ee/cryptish"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {

	r1 := chi.NewRouter()
	r1.Use(middleware.Logger)
	r1.Handle("/", ch.Ge2ee(testhandler))
	http.ListenAndServe(":1321", r1)
}

func testhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello World")
}
