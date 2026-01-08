package main

import (
	"fmt"
	"log"
	"net/http"
	"report-generator/internal/config"
	"report-generator/internal/handlers"
	"report-generator/internal/logger"
)

func main() {
	logger.Init(config.LogLevel, config.LogFile)
	logger.Info("Starting Report Generator Server")

	// Initialize handlers
	reportHandler := handlers.NewReportHandler()
	uploadHandler := handlers.NewUploadHandler(reportHandler)

	// Setup routes
	http.HandleFunc("/", uploadHandler.ServeUploadPage)
	http.HandleFunc("/upload", uploadHandler.HandleUpload)
	http.HandleFunc("/report", reportHandler.GenerateReport)

	addr := fmt.Sprintf(":%d", config.ServerPort)
	logger.Info(fmt.Sprintf("Server listening on %s", addr))
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
