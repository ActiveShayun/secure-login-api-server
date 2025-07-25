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
    origin: 'http://localhost:5174',
    credentials: true
}))
app.use(cookieParser())



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

        app.post('/signUp', async (req, res) => {
            const { email, password, photo, name } = req.body;
            console.log(email, password);
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
            console.log('signUp result', result);
            res.status(201).json({ message: 'User created successfully' })
        })


        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
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
    console.log(`secure api server in running on port${port}`);
})
