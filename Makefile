# Makefile for cross-compiling a Go program for Windows and Linux

# Define the name of your Go program's main package directory (e.g., "cmd/myprogram")
# If your main.go is directly in the root, use "."
APP_NAME := sridm
MAIN_DIR := .

# Define the output directory for compiled binaries
BUILD_DIR := bin

# Define the source file(s) to compile (usually main.go or a specific package)
# This assumes your main package is in MAIN_DIR
GO_FILES := $(shell find $(MAIN_DIR) -name "*.go")

.PHONY: all clean windows linux

all: windows linux ## Compile for both Windows and Linux

windows: ## Compile for Windows
	@echo "Compiling for Windows ..."
	@mkdir -p $(BUILD_DIR)
	@rm $(BUILD_DIR)/$(APP_NAME).exe
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME).exe $(MAIN_DIR)
	@echo "Windows executable built: $(BUILD_DIR)/$(APP_NAME).exe"

linux: ## Compile for Linux 
	@echo "Compiling for Linux ..."
	@mkdir -p $(BUILD_DIR)
	@rm $(BUILD_DIR)/$(APP_NAME)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_DIR)
	@echo "Linux binary built: $(BUILD_DIR)/$(APP_NAME)"

clean: ## Clean up compiled binaries
	@echo "Cleaning up compiled binaries..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

help: ## Display help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

