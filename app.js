const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3000; // Port 3000 comme dans votre `cat app.js`

// Configuration de la base de données
const db = new sqlite3.Database('./db/database.db', (err) => {
    if (err) {
        console.error("Erreur de connexion à la base de données:", err.message);
    } else {
        console.log('Connecté à la base de données SQLite.');
        // Initialisation de la base de données (création des tables)
        // Les insertions de données initiales sont commentées pour permettre l'insertion via l'interface.
        db.serialize(() => {
            // Table des utilisateurs (pour la connexion)
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )`);

            // Table des étudiants
            db.run(`CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                firstname TEXT NOT NULL,
                lastname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                class TEXT NOT NULL,
                major TEXT NOT NULL,
                registration_date TEXT NOT NULL
            )`);

        });
    }
});


// Middleware (un seul ensemble, les doublons ont été supprimés)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Variable globale simple pour simuler une session utilisateur
let currentUser = null;

// Middleware pour rendre currentUser disponible dans toutes les vues via res.locals
// Cela simplifie le passage de currentUser à chaque appel de res.render
app.use((req, res, next) => {
    res.locals.currentUser = currentUser;
    next();
});

// Helper pour rendre une vue avec le layout
// Ceci est la clé pour que le système de layout fonctionne
const renderWithLayout = (res, viewName, data = {}) => {
    // S'assurer que currentUser est toujours passé à la vue interne
    const viewData = { ...data, currentUser: res.locals.currentUser };

    // Rendre la vue spécifique et récupérer son HTML
    res.render(viewName, viewData, (err, viewHtml) => {
        if (err) {
            console.error(`Erreur lors du rendu de la vue ${viewName}:`, err.message);
            // Si la vue n'est pas trouvée, cela peut être un problème de nom de fichier
            if (err.message.includes('Failed to lookup view')) {
                return res.status(404).send(`Erreur: La vue "${viewName}.ejs" n'a pas été trouvée. Vérifiez le nom du fichier et son emplacement dans /views.`);
            }
            return res.status(500).send("Erreur de rendu de la page.");
        }
        // Rendre le layout, en passant le HTML de la vue comme 'body' et le titre
        res.render('layout', {
            title: data.title || 'Gestion Étudiants', // Utilise le titre passé ou un titre par défaut
            body: viewHtml,
            currentUser: res.locals.currentUser // S'assure que currentUser est toujours disponible dans le layout
        });
    });
};


// Routes

// Page d'accueil
app.get('/', (req, res) => {
    renderWithLayout(res, 'index', { title: "Accueil" });
});

// Page de connexion
app.get('/connexion', (req, res) => {
    renderWithLayout(res, 'login', { title: "Connexion", error: null });
});

// Gérer la connexion (avec vulnérabilité : SQL Injection)
app.post('/connexion', (req, res) => {
    const { username, password } = req.body;

    // VULNERABILITÉ : SQL Injection (sans requêtes préparées)
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(sql, (err, user) => {
        if (err) {
            console.error("Erreur de connexion:", err.message);
            return renderWithLayout(res, 'login', { title: "Connexion", error: "Erreur serveur lors de la connexion." });
        }
        if (user) {
            currentUser = user.username; // Simuler la connexion
            res.redirect('/students');
        } else {
            renderWithLayout(res, 'login', { title: "Connexion", error: "Nom d'utilisateur ou mot de passe incorrect." });
        }
    });
});

// Page d'inscription
app.get('/inscription', (req, res) => {
    renderWithLayout(res, 'register', { title: "Inscription", error: null });
});

// Gérer l'inscription (avec vulnérabilité : XSS potentiel dans le nom si non échappé)
app.post('/inscription', (req, res) => {
    const { firstname, lastname, username, email, class: studentClass, major, password, confirm_password } = req.body;

    if (password !== confirm_password) {
        return renderWithLayout(res, 'register', { title: "Inscription", error: "Les mots de passe ne correspondent pas." });
    }

    // VULNERABILITÉ : Mot de passe en clair (ne pas faire en production)
    const userSql = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(userSql, [username, password], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return renderWithLayout(res, 'register', { title: "Inscription", error: "Ce nom d'utilisateur est déjà pris." });
            }
            console.error("Erreur lors de l'inscription de l'utilisateur:", err.message);
            return renderWithLayout(res, 'register', { title: "Inscription", error: "Erreur serveur lors de l'inscription de l'utilisateur." });
        }

        // Ajout de l'étudiant
        const studentSql = `INSERT INTO students (firstname, lastname, email, class, major, registration_date) VALUES (?, ?, ?, ?, ?, ?)`;
        const registration_date = new Date().toLocaleDateString('fr-FR'); // Format DD/MM/YYYY
        db.run(studentSql, [firstname, lastname, email, studentClass, major, registration_date], function(err) {
            if (err) {
                console.error("Erreur lors de l'inscription de l'étudiant:", err.message);
                // Si l'insertion de l'étudiant échoue mais l'utilisateur est créé, c'est une bizarrerie pour l'exemple.
                // En production, il faudrait rollback ou gérer ça mieux.
                // Pour l'instant, on se contente de signaler l'erreur
                return renderWithLayout(res, 'register', { title: "Inscription", error: "Erreur serveur lors de l'inscription de l'étudiant." });
            }
            currentUser = username;
            res.redirect('/students');
        });
    });
});

// Déconnexion
app.get('/deconnexion', (req, res) => {
    currentUser = null;
    res.redirect('/');
});


// Middleware pour vérifier l'authentification (simple)
function requireAuth(req, res, next) {
    if (currentUser) {
        next();
    } else {
        res.redirect('/connexion');
    }
}

// Liste des étudiants (avec restriction d'accès)
app.get('/students', (req, res) => {
    const query = req.query.search || '';
    let sql = `SELECT * FROM students`;
    const params = [];

    // VULNERABILITÉ : SQL Injection via le paramètre de recherche (si non nettoyé)
    if (query) {
        sql += ` WHERE firstname LIKE '%${query}%' OR lastname LIKE '%${query}%' OR email LIKE '%${query}%'`;
    }

    db.all(sql, params, (err, students) => {
        if (err) {
            console.error("Erreur lors de la récupération des étudiants:", err.message);
            return res.status(500).send("Erreur serveur");
        }
        renderWithLayout(res, 'students', { title: "Liste des étudiants", students: students, search: query });
    });
});

// Détails d'un étudiant (avec vulnérabilité : XSS potentiel via ID si non validé)
app.get('/student/:id', requireAuth, (req, res) => {
    const studentId = req.params.id;

    // VULNERABILITÉ : XSS potentiel si studentId contient du JS malveillant et est réfléchi sans échappement
    // VULNERABILITÉ : SQL Injection si studentId est directement injecté sans validation/paramétrage
    const sql = `SELECT * FROM students WHERE id = ${studentId}`;

    db.get(sql, (err, student) => {
        if (err) {
            console.error("Erreur lors de la récupération de l'étudiant:", err.message);
            return res.status(500).send("Erreur serveur");
        }
        if (student) {
            renderWithLayout(res, 'student-details', { title: "Détails de l'étudiant", student: student });
        } else {
            res.status(404).send("Étudiant non trouvé");
        }
    });
});

// Démarrez le serveur
app.listen(port, () => {
    console.log(`Application de gestion des étudiants lancée sur http://localhost:${port}`);
});
