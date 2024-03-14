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

//API 6
app.get('/tweets/:tweetId/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const tweetId = request.params.tweetId

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Check if the tweet belongs to the user or the user is following the tweet owner
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
      // Retrieve tweet details: tweet, likes count, replies count, and date-time
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
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

// API7
app.get(
  '/tweets/:tweetId/likes/',
  authenticatejwt,
  async (request, response) => {
    const currentUser = request.user.username
    const tweetId = request.params.tweetId

    try {
      // Retrieve user_id of the current user
      const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
      const {user_id} = await db.get(getUserIdQuery, [currentUser])

      // Check if the tweet belongs to the user or the user is following the tweet owner
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
        // Retrieve the list of usernames who liked the tweet
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
    } catch (error) {
      console.log(`DB Error: ${error.message}`)
      response.status(500).send('Internal Server Error')
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

    try {
      // Retrieve user_id of the current user
      const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
      const {user_id} = await db.get(getUserIdQuery, [currentUser])

      // Check if the tweet belongs to the user or the user is following the tweet owner
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
        // Retrieve the list of replies
        const repliesQuery = `
        SELECT u.name, r.reply
        FROM reply AS r
        INNER JOIN user AS u ON r.user_id = u.user_id
        WHERE r.tweet_id = ?
      `
        const replies = await db.all(repliesQuery, [tweetId])

        response.json({replies})
      }
    } catch (error) {
      console.log(`DB Error: ${error.message}`)
      response.status(500).send('Internal Server Error')
    }
  },
)

// API 9

app.get('/user/tweets/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Retrieve all tweets of the user along with likes count, replies count, and date-time
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
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

//API 10
app.post('/user/tweets/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const {tweet} = request.body

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Insert the new tweet into the tweet table
    const createTweetQuery = `
      INSERT INTO tweet (tweet, user_id, date_time)
      VALUES (?, ?, datetime('now'))
    `
    await db.run(createTweetQuery, [tweet, user_id])

    response.send('Created a Tweet')
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

//API 11
app.delete('/tweets/:tweetId/', authenticatejwt, async (request, response) => {
  const currentUser = request.user.username
  const tweetId = request.params.tweetId

  try {
    // Retrieve user_id of the current user
    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [currentUser])

    // Check if the tweet belongs to the user
    const checkTweetOwnershipQuery = `SELECT user_id FROM tweet WHERE tweet_id = ?`
    const {user_id: tweetOwnerId} = await db.get(checkTweetOwnershipQuery, [
      tweetId,
    ])

    if (!tweetOwnerId || user_id !== tweetOwnerId) {
      response.status(401).send('Invalid Request')
    } else {
      // Delete the tweet
      const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ?`
      await db.run(deleteTweetQuery, [tweetId])

      response.send('Tweet Removed')
    }
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

module.exports = app
