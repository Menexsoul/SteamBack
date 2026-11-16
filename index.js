import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { DatabaseSync } from 'node:sqlite';

const database = new DatabaseSync('./apidatabase.db');
const app = express();
const port = 8080;

const JWT_SECRET = 'cle_secrete_steam_api_2026';

app.use(cors({
    origin: 'http://localhost:5173',
}));
app.use(express.json());

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}
function initAuthSchema() {
    try {
        database.exec('ALTER TABLE Utilisateurs ADD COLUMN MotDePasse TEXT');
    } catch (e) {  }

    try {
        database.exec("ALTER TABLE Utilisateurs ADD COLUMN Role TEXT DEFAULT 'utilisateur'");
    } catch (e) {  }

    const adminCheck = database.prepare("SELECT * FROM Utilisateurs WHERE NomUtilisateur = 'admin'").get();
    if (!adminCheck) {
        const insertAdmin = database.prepare(`
            INSERT INTO Utilisateurs (NomUtilisateur, Email, MotDePasse, Role)
            VALUES ('admin', 'admin@steam.local', ?, 'administrateur')
        `);
        insertAdmin.run(hashPassword('admin123'));
    }
}
initAuthSchema();
function verifierToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Accès refusé : token JWT manquant.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide ou expiré.' });
        }
        req.user = decodedUser;
        next();
    });
}

function verifierAdmin(req, res, next) {
    if (!req.user || req.user.Role !== 'administrateur') {
        return res.status(403).json({
            error: 'Accès interdit : privilèges administrateur requis pour effectuer cette action.'
        });
    }
    next();
}

app.get('/jeux', (req, res) => {
    const jeuxQuery = database.prepare('SELECT * FROM Jeux');
    res.json(jeuxQuery.all());
});

app.get('/jeux/:id', (req, res) => {
    const jeuQuery = database.prepare('SELECT * FROM Jeux WHERE JeuID = ?');
    const jeu = jeuQuery.get(req.params.id);
    if (jeu) {
        res.json(jeu);
    } else {
        res.status(404).json({ error: 'Jeu non trouvé' });
    }
});

app.post('/jeux', verifierToken, verifierAdmin, (req, res) => {
    const { Titre, Developpeur, Editeur, DateSortie, Image, Prix } = req.body;

    if (!Titre || !Developpeur || !Editeur || !Image || Prix === undefined) {
        return res.status(400).json({
            error: 'Les champs Titre, Developpeur, Editeur, Image et Prix sont obligatoires.'
        });
    }

    try {
        const insertJeu = database.prepare(`
            INSERT INTO Jeux (Titre, Developpeur, Editeur, DateSortie, Image, Prix)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        const result = insertJeu.run(
            Titre,
            Developpeur,
            Editeur,
            DateSortie || new Date().toISOString().split('T')[0],
            Image,
            Prix
        );

        res.status(201).json({
            message: 'Jeu ajouté au catalogue global Steam avec succès',
            JeuID: Number(result.lastInsertRowid),
            Titre,
            Developpeur,
            Editeur,
            DateSortie: DateSortie || new Date().toISOString().split('T')[0],
            Image,
            Prix
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'ajout du jeu', details: error.message });
    }
});

app.post('/utilisateurs', (req, res) => {
    const { NomUtilisateur, MotDePasse, Email } = req.body;

    if (!NomUtilisateur || !MotDePasse) {
        return res.status(400).json({
            error: 'Le nom d\'utilisateur (NomUtilisateur) et le mot de passe (MotDePasse) sont requis.'
        });
    }

    try {
        const motDePasseHache = hashPassword(MotDePasse);
        const userEmail = Email || `${NomUtilisateur.toLowerCase().replace(/\s+/g, '')}@steam.local`;
        const roleParDefaut = 'utilisateur';

        const insertUser = database.prepare(`
            INSERT INTO Utilisateurs (NomUtilisateur, Email, MotDePasse, Role) 
            VALUES (?, ?, ?, ?)
        `);
        const result = insertUser.run(NomUtilisateur, userEmail, motDePasseHache, roleParDefaut);

        res.status(201).json({
            message: 'Utilisateur créé avec succès',
            UtilisateurID: Number(result.lastInsertRowid),
            NomUtilisateur,
            Email: userEmail,
            Role: roleParDefaut
        });
    } catch (error) {
        res.status(409).json({
            error: 'Ce nom d\'utilisateur ou cet email est déjà utilisé.'
        });
    }
});

app.post('/auth/login', (req, res) => {
    const { NomUtilisateur, MotDePasse } = req.body;

    if (!NomUtilisateur || !MotDePasse) {
        return res.status(400).json({
            error: 'Le nom d\'utilisateur et le mot de passe sont requis.'
        });
    }

    const motDePasseHache = hashPassword(MotDePasse);

    const userQuery = database.prepare(`
        SELECT UtilisateurID, NomUtilisateur, Email, Role, DateInscription 
        FROM Utilisateurs 
        WHERE NomUtilisateur = ? AND MotDePasse = ?
    `);
    const utilisateur = userQuery.get(NomUtilisateur, motDePasseHache);

    if (!utilisateur) {
        return res.status(401).json({
            error: 'Identifiants invalides (nom d\'utilisateur ou mot de passe incorrect).'
        });
    }

    const roleUtilisateur = utilisateur.Role || 'utilisateur';

    const token = jwt.sign(
        {
            UtilisateurID: utilisateur.UtilisateurID,
            NomUtilisateur: utilisateur.NomUtilisateur,
            Role: roleUtilisateur
        },
        JWT_SECRET,
        { expiresIn: '2h' }
    );

    res.status(200).json({
        message: 'Connexion réussie',
        token,
        utilisateur: {
            ...utilisateur,
            Role: roleUtilisateur
        }
    });
});

app.get('/utilisateurs', verifierToken, (req, res) => {
    const utilisateursQuery = database.prepare('SELECT UtilisateurID, NomUtilisateur, Email, Role, DateInscription FROM Utilisateurs');
    res.json(utilisateursQuery.all());
});

app.get('/utilisateurs/:id', verifierToken, (req, res) => {
    if (req.user.UtilisateurID !== Number(req.params.id) && req.user.Role !== 'administrateur') {
        return res.status(403).json({ error: 'Accès interdit : vous ne pouvez consulter que votre propre profil.' });
    }

    const utilisateurQuery = database.prepare('SELECT UtilisateurID, NomUtilisateur, Email, Role, DateInscription FROM Utilisateurs WHERE UtilisateurID = ?');
    const utilisateur = utilisateurQuery.get(req.params.id);
    if (utilisateur) {
        res.json(utilisateur);
    } else {
        res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
});

app.get('/utilisateurs/:idUser/bibliothequejeux', verifierToken, (req, res) => {
    const { idUser } = req.params;

    if (req.user.UtilisateurID !== Number(idUser) && req.user.Role !== 'administrateur') {
        return res.status(403).json({ error: 'Accès interdit : cette bibliothèque ne vous appartient pas.' });
    }

    const biblioQuery = database.prepare(`
        SELECT rowid AS BibliothequeID, UtilisateurID, JeuID, HeuresJeu, EstInstalle
        FROM BibliothequeJeux
        WHERE UtilisateurID = ?
    `);
    res.json(biblioQuery.all(idUser));
});

app.delete('/utilisateurs/:idUser/bibliothequejeux/:jeuId', verifierToken, (req, res) => {
    const { idUser, jeuId } = req.params;

    if (req.user.UtilisateurID !== Number(idUser) && req.user.Role !== 'administrateur') {
        return res.status(403).json({ error: 'Accès interdit : vous ne pouvez pas modifier la bibliothèque d\'un autre utilisateur.' });
    }

    const selectQuery = database.prepare(`
        SELECT rowid AS BibliothequeID, UtilisateurID, JeuID, HeuresJeu, EstInstalle
        FROM BibliothequeJeux
        WHERE UtilisateurID = ? AND JeuID = ?
    `);
    const jeuASupprimer = selectQuery.get(idUser, jeuId);

    if (!jeuASupprimer) {
        return res.status(404).json({ error: 'Jeu non trouvé dans la bibliothèque de cet utilisateur' });
    }

    const deleteQuery = database.prepare(`
        DELETE FROM BibliothequeJeux 
        WHERE UtilisateurID = ? AND JeuID = ?
    `);
    deleteQuery.run(idUser, jeuId);

    res.status(200).json(jeuASupprimer);
});

app.put('/utilisateurs/:idUser/bibliothequejeux/:jeuId', verifierToken, (req, res) => {
    const { idUser, jeuId } = req.params;

    if (req.user.UtilisateurID !== Number(idUser) && req.user.Role !== 'administrateur') {
        return res.status(403).json({ error: 'Accès interdit : vous ne pouvez pas modifier la bibliothèque d\'un autre utilisateur.' });
    }

    const { EstInstalle } = req.body;
    const nouvelleValeur = EstInstalle ? 1 : 0;

    const updateQuery = database.prepare(`
        UPDATE BibliothequeJeux 
        SET EstInstalle = ? 
        WHERE UtilisateurID = ? AND JeuID = ?
    `);
    const result = updateQuery.run(nouvelleValeur, idUser, jeuId);

    if (result.changes === 0) {
        return res.status(404).json({ error: 'Jeu non trouvé dans la bibliothèque' });
    }

    const updatedRow = database.prepare(`
        SELECT rowid AS BibliothequeID, UtilisateurID, JeuID, HeuresJeu, EstInstalle
        FROM BibliothequeJeux 
        WHERE UtilisateurID = ? AND JeuID = ?
    `).get(idUser, jeuId);

    res.status(200).json(updatedRow);
});

app.post('/achats', verifierToken, (req, res) => {
    const { JeuID, UtilisateurID } = req.body;

    if (!JeuID || !UtilisateurID) {
        return res.status(400).json({ error: 'JeuID et UtilisateurID sont requis' });
    }

    if (req.user.UtilisateurID !== Number(UtilisateurID)) {
        return res.status(403).json({ error: 'Accès interdit : vous ne pouvez pas effectuer un achat pour un autre utilisateur.' });
    }

    try {
        const insertAchat = database.prepare(`
            INSERT INTO Achats (UtilisateurID, JeuID) VALUES (?, ?)
        `);
        const achatResult = insertAchat.run(UtilisateurID, JeuID);

        const insertBiblio = database.prepare(`
            INSERT INTO BibliothequeJeux (UtilisateurID, JeuID, HeuresJeu, EstInstalle) 
            VALUES (?, ?, 0, 0)
        `);
        insertBiblio.run(UtilisateurID, JeuID);

        res.status(201).json({
            AchatID: Number(achatResult.lastInsertRowid),
            UtilisateurID,
            JeuID,
            DateAchat: new Date().toISOString()
        });
    } catch (error) {
        res.status(409).json({
            error: 'Impossible d\'effectuer l\'achat (le jeu est probablement déjà possédé)',
            details: error.message
        });
    }
});


app.listen(port, () => {
    console.log(`L'API Steam écoute sur le port ${port}`);
});