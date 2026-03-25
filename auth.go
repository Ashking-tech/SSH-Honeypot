package main

// import(
// 	"net/http"
// )

// func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
//     return func(w http.ResponseWriter, r *http.Request) {
//         user, pass, ok := r.BasicAuth()
//         if !ok || user != "ash" || pass != "ash" {
//             w.Header().Set("WWW-Authenticate", `Basic realm="Honeypot API"`)
//             http.Error(w, "Unauthorized", http.StatusUnauthorized)
//             return
//         }
//         next(w, r)
//     }
// }