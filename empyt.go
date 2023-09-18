func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/upload", uploadHandler).Methods("POST")
	router.HandleFunc("/list", listHandler).Methods("GET")
	router.HandleFunc("/delete/{filename}", deleteHandler).Methods("POST")
	router.HandleFunc("/download/{filename}", downloadHandler).Methods("GET")

	fs := http.FileServer(http.Dir("uploads"))
	router.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", fs))

	fmt.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", router)
}


func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/delete/", deleteHandler)
	http.HandleFunc("/download/", downloadHandler)

	fs := http.FileServer(http.Dir("uploads"))
	http.Handle("/uploads/", http.StripPrefix("/uploads/", fs))

	fmt.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", nil)
}

