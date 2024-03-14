const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const path = require('path')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')

let db = null

const initializeDBServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(4000, () => {
      console.log('Server Running At http://localhost:3000')
    })
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
  }
}

initializeDBServer()

app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const checkUsernamePresentQuery = `
    SELECT * FROM user WHERE username = ?;`

  try {
    const dbResponse = await db.get(checkUsernamePresentQuery, [username])

    if (dbResponse !== undefined) {
      response.status(400)
      response.send('User already exists')
    } else if (password.length < 6) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const hashedPassword = await bcrypt.hash(password, 10)
      const registerUserQuery = `
        INSERT INTO user (username, password, name, gender)
        VALUES (?, ?, ?, ?);`
      await db.run(registerUserQuery, [username, hashedPassword, name, gender])
      response.status(200)
      response.send('User created successfully')
    }
  } catch (error) {
    console.log(`Error: ${error.message}`)
    response.status(500)
    response.send('Internal Server Error')
  }
})

// middelware for jwt token
const authenticatejwt = (request, response, next) => {
  const token = request.headers.authorization
  if (!token) {
    return response.status(401).json({message: 'Invalid JWT Token'})
  }
  jwt.verify(token.split(' ')[1], 'MY_SECRET_KEY', (err, decoded) => {
    if (err) {
      return response.status(401).json({message: 'Invalid JWT Token'})
    }
    request.user = decoded
    next()
  })
}

app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const checkUserPresentOrNot = `SELECT * FROM user WHERE username = ?`
  try {
    const dataBaseUser = await db.get(checkUserPresentOrNot, [username])
    if (dataBaseUser === undefined) {
      response.status(400).send('Invalid user')
    } else {
      const isPassMatch = await bcrypt.compare(password, dataBaseUser.password)
      if (isPassMatch) {
        const payload = {username: username}
        const jwtToken = jwt.sign(payload, 'MY_SECRET_KEY')
        response.send(jwtToken)
      } else {
        response.status(400).send('Invalid password')
      }
    }
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

// Protected route example
app.get('/protected', authenticatejwt, (request, response) => {
  response.send('You are authorized')
})

app.get('/user/tweets/feed/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Retrieve tweets from users whom the current user follows
    const tweetFeedQuery = `
      SELECT u.username, t.tweet, t.date_time AS dateTime
      FROM tweet AS t
      INNER JOIN follower AS f ON t.user_id = f.following_user_id
      INNER JOIN user AS u ON t.user_id = u.user_id
      WHERE f.follower_user_id = ?
      ORDER BY t.date_time DESC
      LIMIT 4`

    const tweets = await db.all(tweetFeedQuery, [user_id])
    response.json(tweets)
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

module.exports = app

// API 4
app.get('/user/following/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Retrieve names of people whom the current user follows
    const listOfFollowingQuery = `
      SELECT u.name
      FROM user AS u
      INNER JOIN follower AS f ON u.user_id = f.following_user_id
      WHERE f.follower_user_id = ?`

    const followingList = await db.all(listOfFollowingQuery, [user_id])
    response.json(followingList)
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

//API 5
app.get('/user/followers/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  try {
    const userQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(userQuery, [currentUser])

    const listOfFollwPeople = `SELECT u.name 
                          FROM user AS u 
                          INNER JOIN follower AS f ON u.user_id = f.follower_id
                          WHERE f.following_user_id = ?`
    const dbResponse = await db.all(listOfFollwPeople, [user_id])
    response.json(dbResponse)
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})
