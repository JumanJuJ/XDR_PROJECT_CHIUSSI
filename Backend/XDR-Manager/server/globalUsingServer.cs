global using System;
global using System.Collections.Concurrent;
global using System.Collections.Generic;
global using System.Threading;
global using System.Threading.Tasks;

global using Microsoft.AspNetCore.Mvc;

global using MongoDB.Bson;
global using MongoDB.Driver;

global using Newtonsoft.Json.Linq;

global using CreatingCaptureFile;
global using ErrorHandler;

global using XDR.Manager.ArpDtoNamespace;
global using XDR.Manager.EthDtoNamespace;
global using XDR.Manager.IpDtoNamespace;
global using XDR.Manager.MapperNamespace;
global using XDR.Manager.NetworkInfoNamespace;
global using XDR.Manager.Response;
global using XDR.Manager.TcpDtoNamespace;
global using XDR.Manager.fileModel;

global using XDR_Classes.processModel;


global using XDR_Detection.utils;
global using XDR.Detection.Detector;

