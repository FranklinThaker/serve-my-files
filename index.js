#!/usr/bin/env node

const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const os = require("os");
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const bcrypt = require("bcrypt");

const argv = yargs(hideBin(process.argv)).argv;
const PORT = argv.port || 5000;
const PASSWORD = argv.password || null;
const mimeTypes = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpg",
  ".gif": "image/gif",
  ".wav": "audio/wav",
  ".mp4": "video/mp4",
  ".woff": "application/font-woff",
  ".ttf": "application/font-ttf",
  ".eot": "application/vnd.ms-fontobject",
  ".otf": "application/font-otf",
  ".svg": "application/image/svg+xml",
};

let passwordHash = null;

if (PASSWORD) {
  bcrypt.hash(PASSWORD, 10, (err, hash) => {
    if (err) {
      console.error("Error generating password hash:", err);
      process.exit(1);
    } else {
      passwordHash = hash;
      startServer();
    }
  });
} else {
  startServer();
}

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const iface in interfaces) {
    for (const alias of interfaces[iface]) {
      if (alias.family === "IPv4" && !alias.internal) {
        return alias.address;
      }
    }
  }
  return "localhost";
}

function startServer() {
  const server = http.createServer((req, res) => {
    if (passwordHash && !authenticate(req)) {
      res.writeHead(401, {
        "WWW-Authenticate": 'Basic realm="Protected Area"',
      });
      res.end("Authentication required.");
      return;
    }

    const parsedUrl = url.parse(req.url);
    let pathname = path.join(
      process.cwd(),
      decodeURIComponent(parsedUrl.pathname)
    );

    fs.stat(pathname, (err, stats) => {
      if (err) {
        res.writeHead(404);
        res.end(`File ${pathname} not found!`);
        return;
      }

      if (stats.isDirectory()) {
        fs.readdir(pathname, (err, files) => {
          if (err) {
            res.writeHead(500);
            res.end(`Error reading directory: ${err}.`);
            return;
          }

          res.writeHead(200, { "Content-Type": "text/html" });
          res.write("<html><body><ul>");
          files.forEach((file) => {
            const fileLink = path
              .join(parsedUrl.pathname, file)
              .replace(/\\/g, "/"); // For Windows compatibility
            res.write(`<li><a href="${fileLink}">${file}</a></li>`);
          });
          res.end("</ul></body></html>");
        });
      } else {
        const fileStream = fs.createReadStream(pathname);
        const ext = path.parse(pathname).ext;
        res.writeHead(200, {
          "Content-Type": mimeTypes[ext] || "application/octet-stream",
        });
        fileStream.pipe(res);
      }
    });
  });

  server.listen(PORT, getLocalIP(), () => {
    console.log(`Server is running on http://${getLocalIP()}:${PORT}`);
    if (PASSWORD) {
      console.log("Password protection is enabled.");
    } else {
      console.log(
        "No password protection. Accessible by anyone on the local network."
      );
    }
  });
}

function authenticate(req) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return false;

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [_, password] = credentials.split(":"); // Only extract the password part

  return bcrypt.compareSync(password, passwordHash);
}
