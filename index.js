/*
 * Copyright (c) 2024 Famous Tech && Famous-Tech-Group
 * Tous droits réservés.
 *
 * Ce SaaS est la propriété de Famous Tech et est protégé par les lois sur le droit d'auteur.
 * Toute reproduction, distribution ou utilisation non autorisée de ce logiciel est strictement interdite.
 * Pour obtenir une licence ou des informations supplémentaires, veuillez contacter Famous Tech
 *
 * Famous-Tech-Group 
 * Haïti
 * 1509 43782508 
 * famoustechht@gmail.com
 */

const express = require("express");
const morgan = require("morgan");
const multer = require("multer");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const basicAuth = require("basic-auth");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration de sécurité avancée
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "https://cdn.tailwindcss.com"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.disable("x-powered-by");

// Configuration des sessions
app.use(
  session({
    secret: "famous-secret-key-with-extra-randomnessoejeneo283hru292jdd-2024", // Ceci est un code de sécurité pour les cookies
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: process.env.NODE_ENV === 'production', // Secure en production
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 heures
    }
  })
);

// Middleware pour initialiser les statistiques de l'utilisateur
app.use((req, res, next) => {
  if (!req.session.stats) {
    req.session.stats = { success: 0, failed: 0 };
  }
  next();
});

// Limite de requêtes
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Trop de requêtes, veuillez réessayer plus tard.",
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: "Limite de requêtes API atteinte.",
});

// Filtrage des fichiers
const fileFilter = (req, file, cb) => {
  // Accepte tous les types de fichiers
  cb(null, true);
};

// Stockage des fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(16).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, `${file.originalname}-${uniqueSuffix}${ext}`);
  },
});

const upload = multer({ 
  storage, 
  fileFilter, 
  limits: { fileSize: 1 * 1024 * 1024 * 1024 }, // ceci est équivalent à 1 Go 
});

// Middleware
app.use(morgan("combined"));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Authentification admin
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Famous-Tech";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Famous1609";

const adminAuth = (req, res, next) => {
  const user = basicAuth(req);

  if (user && user.name === ADMIN_USERNAME && user.pass === ADMIN_PASSWORD) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Admin Panel"');
  res.status(401).render('error', { message: "Accès refusé à l'administration" });
};

// Routes
app.get("/", (req, res) => {
  res.render("index", { stats: req.session.stats });
});

app.post("/upload", uploadLimiter, upload.single("file"), (req, res) => {
  if (req.file) {
    req.session.stats.success += 1; 
    // Modification légère pour cacher des détails sensibles
    const safeFile = {
      originalname: req.file.originalname,
      size: req.file.size,
      filename: req.file.filename.split('-')[1].substring(0, 8) // Montre un court extrait unique
    };
    res.render("upload-success", { file: safeFile });
  } else {
    req.session.stats.failed += 1;
    res.status(400).render("error", { message: "Aucun fichier ou type non autorisé !" });
  }
});

app.get("/admin", adminAuth, (req, res) => {
  try {
    const files = fs.readdirSync(path.join(__dirname, "uploads")).map((file) => ({
      name: file,
      size: fs.statSync(path.join(__dirname, "uploads", file)).size,
    }));
    res.render("admin-panel", { files });
  } catch (err) {
    res.status(500).render("error", { message: "Erreur lors de la récupération des fichiers" });
  }
});

// Protection contre l'accès direct aux fichiers
app.get("/uploads/*", (req, res) => {
  res.status(403).render("error", { message: "Accès non autorisé" });
});

// Gestion des erreurs
app.use((req, res) => {
  res.status(404).render("error", { message: "Page non trouvée" });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("error", { message: "Erreur interne" });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur actif sur http://localhost:${PORT}`);
});
