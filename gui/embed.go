package gui

import "embed"

//go:embed index.html style.css app.js
var StaticFiles embed.FS
