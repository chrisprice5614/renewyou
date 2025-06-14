require("dotenv").config() // Makes it so we can access .env file
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const bcrypt = require("bcrypt") //npm install bcrypt
const cookieParser = require("cookie-parser")//npm install cookie-parser
const express = require("express")//npm install express
const db = require("better-sqlite3")("data.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const path = require('path');
const nodemailer = require("nodemailer")
const multer = require("multer")
const sharp = require('sharp');
const fs = require("fs");
const fileStorageEngine = multer.diskStorage({
    
    destination: (req, file, cb) => {
        cb(null, "./public/img")

    },
    filename: (req, file, cb) => {

            const uniqueSuffix = Date.now() + "-" + Math.round(Math.random()*1e9);
            cb(null, uniqueSuffix + path.extname(file.originalname))

    }
    });
const upload = multer({storage: fileStorageEngine, fileFilter: (req, file, cb) => {
    const mime = file.mimetype;
    const allowedTypes = [
      'video/mp4',
      'image/jpeg',
      'image/png',
    ];

    if (allowedTypes.includes(mime)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
}})

const fileSizeLimiter = (req, res, next) => {
    const file = req.file;
    if (!file) return next();
  
    const mime = file.mimetype;
    const size = file.size;
  
    const limits = {
      'image/jpeg': 12 * 1024 * 1024,        // 3 MB
      'image/png': 12 * 1024 * 1024,
      'video/mp4': 12 * 1024 * 1024,       // 12 MB (mp3)
    };
  
    const limit = limits[mime];
    if (limit && size > limit) {
      return res.status(400).json({ error: `File too large. Limit is ${limit / (1024 * 1024)}MB.` });
    }
  
    next();
};

db.pragma("journal_mode = WAL")

//mailing function
async function sendEmail(to, subject, html) {
    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.MAILNAME,
            pass: process.env.MAILSECRET
        },
        tls: {
            rejectUnauthorized: false
        }
    });


    let info = await transporter.sendMail({
        from: '"Chris Price Music" <info@chrispricemusic.net>',
        to: to,
        subject: subject,
        html: `<html>
        <head>
            <title>Check it out!</title>
            <link rel="icon" type="image/x-icon" href="https://www.dropbox.com/scl/fi/cvyp68qqihaakktohzyt8/favicon.ico?dl=1">
            <link href="https://fonts.googleapis.com/css2?family=Open+Sans:ital,wght@0,300..800;1,300..800&family=Oswald:wght@200..700&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://use.typekit.net/ayz5zyc.css">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, a, abbr, acronym, address, big, cite, code, del, dfn, em, font, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, caption {
                    margin: 0;
                    padding: 0;
                    border: 0;
                    outline: 0;
                    vertical-align: baseline;
                    background: transparent;
                    font-family: "Open Sans", sans-serif;
                    font-weight: 400;
                    font-style: normal;
                    line-height: 1.4em;
                    word-wrap: break-word;
                }
                
                :root{

                --background-dark:rgb(0, 0, 0);
                --background-light:rgb(0, 0, 0);
                --color-light: #0d0b0e;
                --color-dark: #211825;
                --color-primary: #b026ff;
                --color-primary-active: #5d00b1;
                --color-secondary: #00d2b8;
                --color-secondary-active: #009784;
                --border-width: 1.5px;
                --color-reverse: #333;
                }

                body{
                    color: var(--color-light);
                }

                i {
                    font-style: italic;
                }


                h1, h2, h3, h4, h5{
                    margin: 12px;
                    font-family: "quicksand", sans-serif;
                    font-weight: 700;
                    font-style: normal;
                }

                a{
                    color: var(--color-light);
                    font-weight: 600;
                }

                a:hover{
                    color: var(--color-primary)
                }
                .card{
                    margin-top: 10px;
                    padding: 12px;
                    background-color: var(--color-primary);
                    box-shadow: 2px 2px 0px var(--color-dark);

                }

                .card a:hover{
                    color: var(--color-primary-active);
                }

                .card small{
                    color: var(--color-light);
                }

                hr{
                    width: 80%;
                    border-color: var(--color-primary)
                }

                .grid{
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                }

                @media only screen and (width<=1000px){
                    .grid{
                        grid-template-columns: 1fr;
                        margin-left: 8px;
                        margin-right: 8px;
                    }
                }

                p{
                    margin: 12px;
                }
            </style>
        </head>
        <header style="text-align: center;">
            <br>
            <img src="https://raw.githubusercontent.com/chrisprice5614/Form-Test/refs/heads/main/logoBlack.png" alt="Chris price music logo" >
            
        </header>
        <body>
            ${html}
        </body>
        <br>
        <hr>
        <footer style="text-align: center;">
            <br>
            <a href="chrispricemusic.net">chrispricemusic.net</a>
            <br>
        </footer>
    </html>
    `

    })

}

const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstname STRING NOT NULL,
        lastname STRING NOT NULL,
        email STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        admin BOOL NOT NULL,
        membership INT,
        owner BOOL NOT NULL,
        verified BOOL NOT NULL,
        emailsecret STRING NOT NULL,
        goals STRING,
        journal STRING,
        calendar STRING,
        todo STRING,
        journey STRING,
        mood STRING,
        victories STRING,
        temptations STRING,
        growth STRING,
        album STRING,
        contacts STRING
        )
        `
    ).run()
})

createTables();

const app = express()
app.use(express.json())
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({extended: false}))// This makes it so we can easily access requests
app.use(express.static("public")) //Using public folder
app.use(cookieParser())
app.use(express.static('/public'));
app.use(body_parser.json())

app.use(function (req, res, next) {
    res.locals.errors = [];

    res.locals.goals = null
    res.locals.journal = null
    res.locals.todo = null
    res.locals.journey = null
    res.locals.mood = null
    res.locals.victories = null
    res.locals.temptations = null
    res.locals.growth = null
    res.locals.album = null
    res.locals.contacts = null
    res.locals.calendar = null

    //Making sure we're logged in
    try {
        const decoded = jwt.verify(req.cookies.renew, process.env.JWTSECRET)
        req.user = decoded


        const adminStatement = db.prepare("SELECT * FROM users WHERE id = ?")
        const thisUser = adminStatement.get(req.user.userid)


        req.admin = thisUser.admin
        req.owner = thisUser.owner


        if(!thisUser.verified)
        {
            req.user = false;
            req.admin = false;
            req.owner = false;

            res.locals.errors.push("Please verify your email.")
        }

        

        if(req.user)
        {
            res.locals.goals = JSON.parse(thisUser.goals) || []
            res.locals.journal = JSON.parse(thisUser.journal) || []
            res.locals.todo = JSON.parse(thisUser.todo) || []
            res.locals.journey = JSON.parse(thisUser.journey) || []
            res.locals.mood = JSON.parse(thisUser.mood) || []
            res.locals.victories = JSON.parse(thisUser.victories) || []
            res.locals.temptations = JSON.parse(thisUser.temptations) || []
            res.locals.growth = JSON.parse(thisUser.growth) || []
            res.locals.album = JSON.parse(thisUser.album) || []
            res.locals.contacts = JSON.parse(thisUser.contacts) || []
            res.locals.calendar = JSON.parse(thisUser.calendar) || []
        }

        


    } catch(err){
        req.user = false
        req.admin = false
        req.owner = false
    }

    res.locals.user = req.user
    res.locals.admin = req.admin
    res.locals.owner = req.owner
    
    

    

    next()
})

function mustBeLoggedIn(req, res, next){
    if(req.user) {
        return next()
    }
    else
    {
        return res.redirect("/login")
    }
}

app.get("/", (req,res) => {
    if(!req.user)
        return res.render("login")

    return res.render("home")
})

app.get("/register", (req,res) => {
    if(req.user)
        return res.render("home")

    return res.render("register")
})

app.get("/login", (req,res) => {
    if(req.user)
        return res.render("home")

    return res.render("login")
})

app.post("/register", (req,res) => {
    const errors = res.locals.errors;

    if (typeof req.body.passwordcheck !== "string") req.body.passwordcheck = ""
    if (typeof req.body.password !== "string") req.body.password = ""
    if (typeof req.body.firstname !== "string") req.body.firstname = ""
    if (typeof req.body.lastname !== "string") req.body.lastname = ""
    if (typeof req.body.email !== "string") req.body.email = ""
    
    req.body.firstname = req.body.firstname.trim()
    req.body.lastname = req.body.lastname.trim()
    req.body.email = req.body.email.trim().toLowerCase()


    if(!req.body.password) errors.push("You must provide a password.")
    if(req.body.password && req.body.password.length < 6) errors.push("Your password must have at least 3 characters")
    if(req.body.password && req.body.password.length > 20) errors.push("Your password can have max 10 characters")

    if(req.body.password != req.body.passwordcheck) errors.push("Your retyped password must match your password.")

    if(!req.body.firstname) errors.push("You must provide a first name.")
    if(!req.body.lastname) errors.push("You must provide a last name.")
    if(!req.body.email) errors.push("You must provide an email.")


    //Check if email exists
    const emailStatement = db.prepare("SELECT * FROM users WHERE email = ?")
    const emailCheck = emailStatement.get(req.body.email)

    
    if(errors.length > 0)
    {
        return res.render("register", {errors})
    }

    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const emailsecret = bcrypt.hashSync(req.body.email + Date.now().toString(), salt).replace(/[^a-zA-Z0-9]/g, '')

    const ourStatement = db.prepare("INSERT INTO users (password, firstname, lastname, email, admin, owner, verified, emailsecret) VALUES (? , ? , ? , ? , ? , ? , ? , ?)")
    const result = ourStatement.run(req.body.password, req.body.firstname, req.body.lastname, req.body.email, 0, 0, 0, emailsecret)

    const html = `<h2>Verify Email</h2>
            <p>Click here to verify email: <a href="${process.env.BASEURL}/verify/`+ emailsecret +`">${process.env.BASEURL}/verify/`+ emailsecret +`</a></p>`

    sendEmail(req.body.email,"Verify Email",html)

    const passEmail = req.body.email;

    res.render("check-email", {passEmail})
})

app.get("/todo", mustBeLoggedIn, (req, res) => {
    return res.render("todo")
})

app.post("/remove-todo", mustBeLoggedIn, (req, res) => {

    res.locals.todo.splice(req.body.index, 1);

    const update = db.prepare("UPDATE users set todo = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.todo),req.user.userid)

    return res.render("todo")
})

app.get("/reflections", mustBeLoggedIn, (req,res) => {
    return res.render("reflections")
})

app.get("/contacts", mustBeLoggedIn, (req,res) => {
    return res.render("contacts")
})

app.post("/add-contact", mustBeLoggedIn, (req,res) => {
    res.locals.contacts.push({name: req.body.name, phone: req.body.phone, description: req.body.description})

    const update = db.prepare("UPDATE users set contacts = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.contacts),req.user.userid)

    return res.render("contacts")
})

app.get("/remove-contact/:id", mustBeLoggedIn, (req,res) => {
    res.locals.contacts.splice(req.params.id, 1);

    const update = db.prepare("UPDATE users set contacts = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.contacts),req.user.userid)

    return res.redirect("/contacts")
})

app.get("/photo-album", mustBeLoggedIn, (req,res) => {

    return res.render("photo-album")
})

app.post('/upload-image', mustBeLoggedIn, upload.single('image'), async (req, res) => {
  try {
    const originalPath = req.file.path; // e.g., uploads/original.jpg
    const filename = path.parse(req.file.filename).name; // without extension
    const newFilename = filename + '.webp';
    const newPath = path.join(path.dirname(originalPath), newFilename);

    // Resize and convert to WebP
    await sharp(originalPath)
      .resize({ width: 640, height: 640, fit: 'inside' }) // Maintain aspect ratio
      .webp({ quality: 80 }) // Adjust quality as needed
      .toFile(newPath);

    // Optionally delete the original file
    fs.unlinkSync(originalPath);

    console.log('Image uploaded and resized:', newFilename);

    res.locals.album.push(newFilename);

    const update = db.prepare("UPDATE users set album = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.album),req.user.userid)

    return res.redirect("/photo-album")
  } catch (error) {
    console.error('Error processing image:', error);
    return res.redirect("/photo-album")
  }
});

app.get("/calming-vibes", mustBeLoggedIn, (req,res) => {
    return res.render("calming-vibes")
})

app.get("/journey", mustBeLoggedIn, (req,res) => {

    return res.render("journey")
})

app.get("/goals", mustBeLoggedIn, (req,res) => {
    return res.render("goals")
})

app.get("/add-goal", mustBeLoggedIn, (req,res) => {
    return res.render("add-goal")
})

app.get("/add-goal/:type", mustBeLoggedIn, (req,res) => {
    const allowedTypes = ["progress", "line", "bar", "pie", "milestone", "scatter", "number"];

    if (!allowedTypes.includes(req.params.type)) {
        return res.redirect("/add-goal");
    }

    const goalType = req.params.type;

    return res.render("create-goal",{goalType})
})

app.post("/create-goal", mustBeLoggedIn, (req,res) => {
    if(req.body.type == "progress")
    {
        res.locals.goals.push({type: req.body.type, startdate: Date.now(), title: req.body.title, description: req.body.description, why: req.body.why, goaldate: new Date(req.body.goaldate).getTime(), singleday: req.body.singleday || 0, variable1: req.body.variable1, color: req.body.color, start: req.body.start, target: req.body.target, percent: req.body.percent || 0})
    }

    if(req.body.type == "number")
    {
        res.locals.goals.push({type: req.body.type, startdate: Date.now(), title: req.body.title, description: req.body.description, why: req.body.why, goaldate: new Date(req.body.goaldate).getTime(), singleday: req.body.singleday || 0, variable1: req.body.variable1, start: req.body.start, target: req.body.target, percent: req.body.percent || 0})
    }

    console.log(req.body.goaldate)

     if(req.body.type == "line")
    {
        res.locals.goals.push({type: req.body.type, startdate: Date.now(), title: req.body.title, description: req.body.description, why: req.body.why, goaldate: new Date(req.body.goaldate).getTime(), singleday: req.body.singleday || 0, variable1: req.body.variable1, color: req.body.color, start: req.body.start, target: req.body.target, data: []})
    }

    if(req.body.type == "milestone")
    {
        res.locals.goals.push({type: req.body.type, startdate: Date.now(), title: req.body.title, description: req.body.description, why: req.body.why})
    }

    

    const update = db.prepare("UPDATE users set goals = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.goals),req.user.userid)

    return res.redirect("/goals")
})

app.post("/update-goal/:id", express.text(), mustBeLoggedIn, (req,res) => {

    const goalType = res.locals.goals[req.params.id].type;
    const data = JSON.parse(req.body);
    console.log("Received beacon data:", data);

    if(data.number)
    {

        if(goalType == "progress")
        {
            const changeStart = data.number;
            res.locals.goals[req.params.id].start = changeStart;
        }

        if(goalType == "number")
        {
            const changeStart = data.number;
            res.locals.goals[req.params.id].start = changeStart;
        }

        if(goalType == "line")
        {
            res.locals.goals[req.params.id].data.push({x: new Date().toISOString(), y: data.number})
        }

        if(goalType == "milestone")
        {
            res.locals.goals[req.params.id].startdate = Date.now();
        }

        const update = db.prepare("UPDATE users set goals = ? WHERE id = ?")
        update.run(JSON.stringify(res.locals.goals),req.user.userid)

        res.status(200).send("OK");
    }
})

app.get("/event/:id", mustBeLoggedIn, (req,res) => {
    return res.render("event", {eventIndex: req.params.id})
})

app.get("/add-event/:id", mustBeLoggedIn, (req,res) => {

    const defaultTime = req.params.id || Date.now()

    console.log(defaultTime)

    return res.render("add-event",{defaultTime})
})


app.post("/add-event", mustBeLoggedIn, (req,res) => {

    

    res.locals.calendar.push({title: req.body.title, datetime: new Date(req.body.datetime).getTime(), description: req.body.description, location: req.body.location, alarm: req.body.alarm})

    const update = db.prepare("UPDATE users set calendar = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.calendar),req.user.userid)

    return res.redirect("/calendar")
})

app.get("/remove-event/:id", mustBeLoggedIn, (req,res) => {
    res.locals.calendar.splice(req.params.id, 1);

    const update = db.prepare("UPDATE users set calendar = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.calendar),req.user.userid)

    return res.redirect("/calendar")
})

app.get("/delete-goal/:id", mustBeLoggedIn, (req,res) => {
    res.locals.goals.splice(req.params.id, 1);

    const update = db.prepare("UPDATE users set goals = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.goals),req.user.userid)

    return res.redirect("/goals")
})

app.get("/goal/:id", mustBeLoggedIn, (req,res) => {
    const goalIndex = req.params.id;

    return res.render("single-goal", {goalIndex})
})

app.get("/calendar", (req, res) => {
  const viewParam = req.query.view || 'today';
  const offsetParam = parseInt(req.query.offset || '0', 10);

  res.render("calendar", {
    viewParam,
    offsetParam
  });
});


app.get("/remove-image/:id", mustBeLoggedIn, (req,res) => {
    const filePath = __dirname+"/public/img/"+res.locals.album[req.params.id]

    res.locals.album.splice(req.params.id, 1);

    fs.unlinkSync(filePath);

    const update = db.prepare("UPDATE users set album = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.album),req.user.userid)

    return res.redirect("/photo-album")
})

app.post("/add-reflection/:id", mustBeLoggedIn, (req,res) => {

    
    switch(req.params.id){
        default: 
            res.locals.mood.unshift({title: req.body.title, text: req.body.reflection, datetime: Date.now()})

            const updateM = db.prepare("UPDATE users set mood = ? WHERE id = ?")
            updateM.run(JSON.stringify(res.locals.mood),req.user.userid)

            return res.render("reflection-log",{reflection: "mood"});
            break;
        case "victories":
            res.locals.victories.unshift({title: req.body.title, text: req.body.reflection, datetime: Date.now()})

            const updateV = db.prepare("UPDATE users set victories = ? WHERE id = ?")
            updateV.run(JSON.stringify(res.locals.victories),req.user.userid)
        
            return res.render("reflection-log",{reflection: "victories"});
            break;
        case "temptations":
                res.locals.temptations.unshift({title: req.body.title, text: req.body.reflection, datetime: Date.now()})

                const updateT = db.prepare("UPDATE users set temptations = ? WHERE id = ?")
                updateT.run(JSON.stringify(res.locals.temptations),req.user.userid)

                return res.render("reflection-log",{reflection: "temptations"});
                break;
        case "growth":
            res.locals.growth.unshift({title: req.body.title, text: req.body.reflection, datetime: Date.now()})

            const updateG = db.prepare("UPDATE users set growth = ? WHERE id = ?")
            updateG.run(JSON.stringify(res.locals.growth),req.user.userid)

            return res.render("reflection-log",{reflection: "growth"});
            break;
    }
})

app.get("/journal", mustBeLoggedIn, (req,res) => {
    return res.render("journal")
})

app.get("/add-journal", mustBeLoggedIn, (req,res) => {
    return res.render("add-journal")
})

app.post("/add-todo", mustBeLoggedIn, (req,res) => {
    res.locals.todo.push(req.body.item)

    const update = db.prepare("UPDATE users set todo = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.todo),req.user.userid)

    return res.render("todo")
})

app.get("/journal-entry/:id", mustBeLoggedIn, (req,res) => {
    console.log(res.locals.journal)
    const entry = res.locals.journal.find(item => item.datetime === Number(req.params.id));

    console.log(entry)

    return res.render("journal-entry", {entry})
})

app.get("/emergency", mustBeLoggedIn, (req,res) => {
    return res.render("emergency")
})

app.post("/add-journal", mustBeLoggedIn, (req,res) => {
    res.locals.journal.unshift({title: req.body.title, text: req.body.text, datetime: Date.now()})

    const update = db.prepare("UPDATE users set journal = ? WHERE id = ?")
    update.run(JSON.stringify(res.locals.journal),req.user.userid)

    return res.render("journal")
})

app.get("/reflections/:id", (req,res) => {
    switch(req.params.id){
        default: return res.render("reflection-log",{reflection: "mood"}); break;
        case "victories": return res.render("reflection-log",{reflection: "victories"}); break;
        case "temptations": return res.render("reflection-log",{reflection: "temptations"}); break;
        case "growth": return res.render("reflection-log",{reflection: "growth"}); break;
    }
})

app.post("/login", (req, res) => {

    let errors = []

    

    if (typeof req.body.email !== "string") req.body.email = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.email = req.body.email.trim().toLowerCase()

    if(req.body.email == "") errors=["Invalid email/password"]
    if(req.body.password == "") errors=["Invalid email/password"]

    if(errors.length) {
        return res.render("login", {errors}) //returning to the login page while also passing the object "errors"
    }

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE EMAIL = ?") //Select *(any) from 'name of table'
    const userInQuestion = userInQuestionStatement.get(req.body.email)

    if(!userInQuestion) {
         errors=["Invalid email/password"]
         return res.render("login", {errors})
    }


    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot)
    {
        errors=["Invalid email/password"]
        return res.render("login", {errors})
    }

    if(!userInQuestion.verified){
        errors=["Please verify your email."]
        return res.render("login", {errors})
    }

    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*24*28), userid: userInQuestion.id, email: userInQuestion.email, name: userInQuestion.firstname}, process.env.JWTSECRET) //Creating a token for logging in

    res.cookie("renew",ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24 * 28
    }) //name, string to remember,

    

    //redirection
    return res.redirect("/")
})

app.get("/verify/:id", (req,res) => {
    try{
        const statement = db.prepare("SELECT * FROM users WHERE emailsecret = ?")
        const userInQuestion = statement.get(req.params.id);

        const update = db.prepare("UPDATE users set verified = 1 WHERE id = ?")
        update.run(userInQuestion.id)


        // log the user in by giving them a cookie
        const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*24*28), userid: userInQuestion.id, email: userInQuestion.email, name: userInQuestion.firstname}, process.env.JWTSECRET) //Creating a token for logging in
        console.log("WHAT THE FUCK")
        res.cookie("renew",ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24 * 28
        }) //name, string to remember,

        return res.render("verified")
    } catch(err)
    {
        return res.redirect("/")
    }
})

app.get("/logout", (req,res) => {
    res.clearCookie("renew")
    res.redirect("/")
})


app.listen(3010)