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
    app.listen(3000, () => {
      console.log('Server Running At http://localhost:3000')
    })
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
  }
}

initializeDBServer()

//API 1
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

// Middleware for jwt token
const authenticatejwt = (request, response, next) => {
  const authHeaders = request.headers['authorization']

  if (!authHeaders || !authHeaders.startsWith('Bearer ')) {
    response.status(401).send('Invalid JWT Token')
    return
  }

  const token = authHeaders.split(' ')[1]

  jwt.verify(token, 'MY_SECRET_KEY', (error, decoded) => {
    if (error) {
      response.status(401).send('Invalid JWT Token')
    } else {
      console.log(decoded)
      request.user = decoded
      next()
    }
  })
}

// API 2
// API 2
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const checkUserPresentOrNot = `SELECT * FROM user WHERE username = ?;`

  try {
    const dbUser = await db.get(checkUserPresentOrNot, [username])

    if (dbUser === undefined) {
      response.status(400)
      response.send('Invalid user')
    } else {
      const isPassMatched = await bcrypt.compare(password, dbUser.password)
      if (isPassMatched === true) {
        const payload = {username: username}
        const jwtToken = jwt.sign(payload, 'MY_SECRET_KEY')
        response.send({jwtToken})
      } else {
        response.status(400)
        response.send('Invalid password')
      }
    }
  } catch (error) {
    console.log(`Error: ${error.message}`)
    response.status(500)
    response.send('Internal Server Error')
  }
})

// API 3
app.get('/user/tweets/feed/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])
  const queryToGetLatestTweet = `SELECT u.username, t.tweet, t.date_time AS dateTime
                  FROM tweet AS t
                  INNER JOIN user AS u ON t.user_id = u.user_id
                  WHERE t.user_id IN (
                      SELECT following_user_id
                      FROM follower
                      WHERE follower_user_id = ?
                  )
                  ORDER BY t.date_time DESC
                  LIMIT 4;`
  const dbResponse = await db.all(queryToGetLatestTweet, [user_id])
  response.send(dbResponse)
})

//API 4
app.get('/user/following/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])
  const followingQuery = `SELECT u.name
      FROM user AS u
      INNER JOIN follower AS f ON u.user_id = f.following_user_id
      WHERE f.follower_user_id = ?`
  const dbResponse = await db.all(followingQuery, [user_id])
  response.send(dbResponse)
})

// API 5
app.get('/user/followers/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])
  const followersQuery = `SELECT u.name
                    FROM user AS u
                    INNER JOIN follower AS f ON u.user_id = f.follower_user_id
                    WHERE f.following_user_id = ?;
                    `
  const dbResponse = await db.all(followersQuery, [user_id])
  response.send(dbResponse)
})

// API 6
app.get('/tweets/:tweetId/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const tweetId = request.params.tweetId

  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])

  const checkTweetOwnershipQuery = `
      SELECT t.tweet_id 
      FROM tweet AS t
      LEFT JOIN follower AS f ON t.user_id = f.following_user_id
      WHERE (t.user_id = ? OR f.follower_user_id = ?) AND t.tweet_id = ?
    `
  const tweet = await db.get(checkTweetOwnershipQuery, [
    user_id,
    user_id,
    tweetId,
  ])

  if (!tweet) {
    response.status(401).send('Invalid Request')
  } else {
    const tweetDetailsQuery = `
        SELECT t.tweet, 
               COUNT(l.like_id) AS likes, 
               COUNT(r.reply_id) AS replies, 
               t.date_time AS dateTime
        FROM tweet AS t
        LEFT JOIN like AS l ON t.tweet_id = l.tweet_id
        LEFT JOIN reply AS r ON t.tweet_id = r.tweet_id
        WHERE t.tweet_id = ?
        GROUP BY t.tweet_id
      `
    const tweetDetails = await db.get(tweetDetailsQuery, [tweetId])

    response.json(tweetDetails)
  }
})

// API 7
app.get(
  '/tweets/:tweetId/likes/',
  authenticatejwt,
  async (request, response) => {
    const currentUser = request.user.username
    const tweetId = request.params.tweetId

    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    const checkTweetOwnershipQuery = `
        SELECT t.tweet_id 
        FROM tweet AS t
        LEFT JOIN follower AS f ON t.user_id = f.following_user_id
        WHERE (t.user_id = ? OR f.follower_user_id = ?) AND t.tweet_id = ?
      `
    const tweet = await db.get(checkTweetOwnershipQuery, [
      user_id,
      user_id,
      tweetId,
    ])

    if (!tweet) {
      response.status(401).send('Invalid Request')
    } else {
      const likedUsersQuery = `
          SELECT u.username
          FROM user AS u
          INNER JOIN like AS l ON u.user_id = l.user_id
          WHERE l.tweet_id = ?
        `
      const likedUsers = await db.all(likedUsersQuery, [tweetId])
      const likes = likedUsers.map(user => user.username)
      response.json({likes})
    }
  },
)

// API 8
app.get(
  '/tweets/:tweetId/replies/',
  authenticatejwt,
  async (request, response) => {
    const currentUser = request.user.username
    const tweetId = request.params.tweetId
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    const checkTweetOwnershipQuery = `
                    SELECT t.tweet_id 
                    FROM tweet AS t
                    LEFT JOIN follower AS f ON t.user_id = f.following_user_id
                    WHERE (t.user_id = ? OR f.follower_user_id = ?) AND t.tweet_id = ?
                  `
    const tweet = await db.get(checkTweetOwnershipQuery, [
      user_id,
      user_id,
      tweetId,
    ])

    if (!tweet) {
      response.status(401).send('Invalid Request')
    } else {
      const repliesQuery = `
                    SELECT u.name, r.reply
                    FROM reply AS r
                    INNER JOIN user AS u ON r.user_id = u.user_id
                    WHERE r.tweet_id = ?
                  `
      const replies = await db.all(repliesQuery, [tweetId])

      response.json({replies})
    }
  },
)

// API 9
app.get('/user/tweets/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])
  const userTweetsQuery = `
          SELECT t.tweet, 
                COUNT(l.like_id) AS likes, 
                COUNT(r.reply_id) AS replies, 
                t.date_time AS dateTime
          FROM tweet AS t
          LEFT JOIN like AS l ON t.tweet_id = l.tweet_id
          LEFT JOIN reply AS r ON t.tweet_id = r.tweet_id
          WHERE t.user_id = ?
          GROUP BY t.tweet_id
          ORDER BY t.date_time DESC
        `
  const userTweets = await db.all(userTweetsQuery, [user_id])
  response.json(userTweets)
})

// API 10
app.post('/user/tweets/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const {tweet} = request.body
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])
  const createTweetQuery = `
      INSERT INTO tweet (tweet)
      VALUES (?)
    `
  await db.run(createTweetQuery, [tweet])
  response.send('Created a Tweet')
})

//API 11

app.delete('/tweets/:tweetId/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const tweetId = request.params.tweetId
  const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
  const {user_id} = await db.get(getUserIdQuery, [currentUser])

  const checkTweetOwnershipQuery = `SELECT user_id FROM tweet WHERE tweet_id = ?`
  const {user_id: tweetOwnerId} = await db.get(checkTweetOwnershipQuery, [
    tweetId,
  ])

  if (!tweetOwnerId || user_id !== tweetOwnerId) {
    response.status(401).send('Invalid Request')
  } else {
    const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ?`
    await db.run(deleteTweetQuery, [tweetId])

    response.send('Tweet Removed')
  }
})

module.exports = app
