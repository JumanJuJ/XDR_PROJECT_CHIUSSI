
global using System;
global using System.Collections.Concurrent;


// =========================
// MongoDB
// =========================
global using MongoDB.Bson;
global using MongoDB.Driver;

// =========================
// JSON
// =========================
global using Newtonsoft.Json;

// =========================
// Shared / Infra
// =========================
global using CreatingCaptureFile;
global using ErrorHandler;

// =========================
// Detection Core
// =========================
global using XDR.Detection.ARPSpoofing;

global using XDR.Detection.utils.PrivilegeEscalation;
global using XDR.Detection.Utils.Sanitizer;
global using XDR.Detection.Utils.SynFlood;

// =========================
// Detection Models
// =========================
global using XDR_Detection.models.WarningLocal;

// =========================
// Shared Models 
// =========================
global using XDR.Manager.fileModel;
global using XDR.Manager.NetworkInfoNamespace;
global using XDR.Manager.utils.counter;

global using XDR.Models.StaticAnalysis;
global using XDR_Classes.processModel;

