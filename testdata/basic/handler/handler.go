package handler

import (
	"net/http"

	"example.com/basic/auth"
)

type ProxyHandler struct{}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	user, err := auth.ValidateToken(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !auth.Authorize(user, nil) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Write([]byte("OK"))
}

type AdminHandler struct{}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	_, _ = auth.ValidateToken(token)
	w.Write([]byte("admin"))
}
