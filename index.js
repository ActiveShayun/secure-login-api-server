require('dotenv').config()
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require('mongodb');



// middleware
app.use(express.json())
app.use(cors({
    origin: [
        'https://verdant-basbousa-9161b1.netlify.app'
    ],
    credentials: true
}))
app.use(cookieParser())


const authenticate = (req, res, next) => {
    const token = req?.cookies?.token;
    if (!token) {
        return res.status(401).json({ message: 'unauthorized' })
    }

    jwt.verify(token, process.env.SECRET_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'unauthorized' })
        }
        // console.log(' decoded user', decoded);
        req.user = decoded
        next()
    })
}



const uri = `mongodb+srv://${process.env.DB_NAME}:${process.env.DB_PASS}@cluster0.fp2vps1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`

// Create a MongoClient with a MongoClientOptions object to set the Stable API version

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});
async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const signUpCollection = client.db('login-db').collection('signup')


        // signup api
        app.post('/signUp', async (req, res) => {
            const { email, password, photo, name } = req.body;
            // console.log(email, password);
            const userExits = await signUpCollection.findOne({ email })

            if (userExits) {
                return res.status(400).json({ message: 'User already exists' })
            }
            const hashPassword = await bcrypt.hash(password, 10);

            const result = await signUpCollection.insertOne({
                photo,
                name,
                email,
                password: hashPassword
            })
            // console.log('signUp result', result);
            // generate token optional because user if want to get his/her profile after signup
            const taken = jwt.sign({ email }, process.env.SECRET_TOKEN, {
                expiresIn: '1h',
            })
            res.cookie('token', taken, {
                httpOnly: true,
                secure: true,
                maxAge: 3600000,
                sameSite: 'None'
            })

                .status(201).json({ message: 'User created successfully' })
        })

        // login api
        app.post('/signin', async (req, res) => {
            const { email, password } = req.body;
            const user = await signUpCollection.findOne({ email })
            if (!user) {
                return res.status(401).json({ message: 'invalid email' })
            }
            const isValid = await bcrypt.compare(password, user.password)
            if (!isValid) {
                return res.status(401).json({ message: 'invalid password' })
            }
            // generate token 
            const taken = jwt.sign({ email }, process.env.SECRET_TOKEN, {
                expiresIn: '1h',
            })

            res.cookie('token', taken, {
                httpOnly: true,
                secure: true,
                maxAge: 3600000,
                sameSite: 'None'
            })
                .status(200).json({
                    success: true,
                    message: 'Logged in successfully done'
                })
        })

        // logout with clear cookie api
        app.post('/logout', (req, res) => {
            res.clearCookie('token', {
                httpOnly: true,
                secure: true,
                sameSite: 'None',
            })
            res.status(200).json({ message: 'Logout successful' })
        })


        // uer profile api
        app.get('/profile', authenticate, async (req, res) => {
            const user = req?.user;
            console.log('profile', user);
            const isUser = await signUpCollection.findOne({ email: user.email })
            if (!isUser) {
                res.status(404).json({ message: 'user not found' })
            }
            // console.log();
            res.send({
                userPhoto: isUser.photo,
                name: isUser.name,
                email: isUser.email
            })
        })



        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('secure api server in running')
})

app.listen(port, () => {
    // console.log(`secure api server in running on port${port}`);
})
