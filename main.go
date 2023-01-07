package main

import (
	ch "ge2ee/cryptish"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {

	r1 := chi.NewRouter()
	//ch.Ge2eetest()
	http.ListenAndServe(":1321", ch.Ge2ee(r1))
}
