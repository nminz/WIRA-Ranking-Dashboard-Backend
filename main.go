package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/patrickmn/go-cache"

	//// 2FA ////
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

//////////// 'Accounts' table model (added 2FA but failed, ignore the pass, 2fa and salt) ////////////

type Accounts struct {
	AccID             int64  `pg:"acc_id,pk"`
	Username          string `pg:"username"`
	Email             string `pg:"email"`
	EncryptedPassword string `pg:"encrypted_password"`
	SecretKey2FA      string `pg:"secretkey_2fa"`
	Salt              string `pg:"salt"`
}

//////////// 'Characters' table model ////////////

type Characters struct {
	CharID  int64 `pg:"char_id,pk"`
	AccID   int64 `pg:"acc_id"`
	ClassID int   `pg:"class_id"`
}

//////////// 'Scores' table model ////////////

type Scores struct {
	ScoreID     int64 `pg:"score_id,pk"`
	CharID      int64 `pg:"char_id"`
	RewardScore int   `pg:"reward_score"`
}

//////////// 'Session' table model ////////////

type Session struct {
	SessionID       int64     `pg:"session_id,pk"`
	SessionMetadata string    `pg:"session_metadata"`
	ExpiryDatetime  time.Time `pg:"expiry_datetime"`
}

////////////////////////////////////////////////////////////// connect to PostgreSQL

func connect() *pg.DB {
	db := pg.Connect(&pg.Options{
		User:     "postgres",
		Password: "oredayak1",
		Addr:     "localhost:5432",
		Database: "wira_db",
	})

	///////////////////////////////////// connection test

	var n int
	_, err := db.QueryOne(pg.Scan(&n), "SELECT 1")
	if err != nil {
		fmt.Println("Could not connect to the database:", err)
		return nil
	}
	fmt.Println("Connected to PostgreSQL successfully!")
	return db
}

/////////////////////////////// create tables in the db if not exist

func createTables(db *pg.DB) {

	if err := db.Model((*Accounts)(nil)).CreateTable(&orm.CreateTableOptions{
		IfNotExists: true,
	}); err != nil {
		fmt.Println("Could not create accounts table:", err)
	}

	if err := db.Model((*Characters)(nil)).CreateTable(&orm.CreateTableOptions{
		IfNotExists: true,
	}); err != nil {
		fmt.Println("Could not create characters table:", err)
	}

	if err := db.Model((*Scores)(nil)).CreateTable(&orm.CreateTableOptions{
		IfNotExists: true,
	}); err != nil {
		fmt.Println("Could not create scores table:", err)
	}

	fmt.Println("Tables checked and created if not existed successfully!")
}

/////////////////////////////// GENERATING FAKE DATA \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

func generateFakeData(db *pg.DB) {

	//////////////////////////// check if accounts already exist

	count, err := db.Model((*Accounts)(nil)).Count()
	if err != nil {
		fmt.Println("Error counting accounts:", err)
		return
	}
	if count > 0 {
		fmt.Println("Data exists, skipping generation.")
		return
	}

	////////////////////////////// generate 100,000 data with gofakeit and insert into wira_db

	for i := 0; i < 100000; i++ {
		account := &Accounts{
			Username: gofakeit.Username(),
			Email:    gofakeit.Email(),
		}
		_, err := db.Model(account).Insert()
		if err != nil {
			fmt.Println("Error inserting account:", err)
			return
		}

		accID := account.AccID

		/////////////////////////// each account, generate 8 characters (classes)

		for j := 0; j < 8; j++ {
			character := &Characters{
				AccID:   accID,
				ClassID: gofakeit.Number(1, 8),
			}

			_, err := db.Model(character).Insert()
			if err != nil {
				fmt.Println("Error inserting character:", err)
				return
			}

			/////////////////////////// each character, generate scores 100-1000

			for k := 0; k < 10; k++ {
				score := &Scores{
					CharID:      character.CharID,
					RewardScore: gofakeit.Number(100, 1000),
				}
				_, err := db.Model(score).Insert()
				if err != nil {
					fmt.Println("Error inserting score:", err)
					return
				}
			}
		}
	}
	fmt.Println("Data generation complete!")
}

////////////////////////////////////// PAGINATION \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

type AccountWithClassAndScore struct {
	AccID    int64  `json:"AccID"`
	Username string `json:"Username"`
	Email    string `json:"Email"`
	ClassID  int    `json:"ClassID"`
	Score    int    `json:"Score"`
	Rank     int    `json:"Rank"` //////field added for ranking
}

func paginatedAccounts(db *pg.DB, c *gin.Context) ([]AccountWithClassAndScore, int, int, error) {
	// Parse query parameters
	page, _ := strconv.Atoi(c.Query("page"))
	limit, _ := strconv.Atoi(c.Query("limit"))
	search := c.Query("search")
	sort := c.Query("sort")
	order := c.Query("order")

	// Set defaults
	if page == 0 {
		page = 1
	}
	if limit == 0 {
		limit = 20
	}
	offset := (page - 1) * limit

	////////////////////////////////// RANKING \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

	baseQuery := `
        WITH ranked_accounts AS (
            SELECT 
                accounts.acc_id,
                accounts.username,
                accounts.email,
                characters.class_id,
                COALESCE(MAX(scores.reward_score), 0) AS score,
                RANK() OVER (ORDER BY COALESCE(MAX(scores.reward_score), 0) DESC) as rank
            FROM accounts
            JOIN characters ON characters.acc_id = accounts.acc_id
            JOIN scores ON scores.char_id = characters.char_id
            GROUP BY accounts.acc_id, accounts.username, accounts.email, characters.class_id
        )
        SELECT * FROM ranked_accounts
    `

	// Add search condition if provided
	var queryParams []interface{}
	if search != "" {
		baseQuery += ` WHERE (username ILIKE ? OR email ILIKE ?)`
		queryParams = append(queryParams, "%"+search+"%", "%"+search+"%")
	}

	// Add sorting logic
	switch sort {
	case "Username":
		if order == "asc" {
			baseQuery += ` ORDER BY username ASC`
		} else {
			baseQuery += ` ORDER BY username DESC`
		}
	case "ClassID":
		if order == "asc" {
			baseQuery += ` ORDER BY class_id ASC`
		} else {
			baseQuery += ` ORDER BY class_id DESC`
		}
	default: // Default sort by score and maintain global rank order
		if order == "asc" {
			baseQuery += ` ORDER BY score ASC, rank DESC`
		} else {
			baseQuery += ` ORDER BY score DESC, rank ASC`
		}
	}

	// Add pagination
	baseQuery += ` LIMIT ? OFFSET ?`
	queryParams = append(queryParams, limit, offset)

	// Execute query
	var results []AccountWithClassAndScore
	var err error

	// Build and execute the final query
	query := db.Model().TableExpr("("+baseQuery+") as ranked", queryParams...)
	err = query.Select(&results)
	if err != nil {
		return nil, 0, 0, err
	}

	// Count total filtered results for pagination

	var total int
	countQuery := `
        WITH ranked_accounts AS (
            SELECT 
                accounts.acc_id,
                accounts.username,
                accounts.email
            FROM accounts
            JOIN characters ON characters.acc_id = accounts.acc_id
            JOIN scores ON scores.char_id = characters.char_id
            GROUP BY accounts.acc_id, accounts.username, accounts.email
        )
        SELECT COUNT(DISTINCT acc_id) FROM ranked_accounts
    `

	if search != "" {
		_, err = db.QueryOne(pg.Scan(&total), countQuery+" WHERE username ILIKE ? OR email ILIKE ?",
			"%"+search+"%", "%"+search+"%")
	} else {
		_, err = db.QueryOne(pg.Scan(&total), countQuery)
	}
	if err != nil {
		return nil, 0, 0, err
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	return results, total, totalPages, nil
}

////////////////////////////////////// SALTING FUNCTION \\\\\\\\\\\\\\\ failed. ignore this function //////////////////////////

func hashPassword(password string) (string, string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	saltStr := base64.StdEncoding.EncodeToString(salt)

	// Combine password with salt and hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return string(hashedPassword), saltStr, nil
}

////////////////////////////////////// MAIN FUNCTION START \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

func main() {
	db := connect()
	if db == nil {
		return ////////// Exit if connection failed
	}

	createTables(db)
	generateFakeData(db)

	////////////////////////////////////////// CACHING START \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

	cacheInstance := cache.New(5*time.Minute, 10*time.Minute)
	r := gin.Default()
	r.Use(cors.Default())

	////////////////////////////////// Route for paginated accounts with caching

	r.GET("/accounts", func(c *gin.Context) {

		// Create a cache key based on the page, limit, and search query parameters

		cacheKey := fmt.Sprintf("accounts_page_%s_limit_%s_search_%s_sort_%s_order_%s",
			c.Query("page"), c.Query("limit"), c.Query("search"), c.Query("sort"), c.Query("order"))

		// Check if cached data exists

		if cachedData, found := cacheInstance.Get(cacheKey); found {
			c.JSON(http.StatusOK, cachedData)
			return
		}

		// Fetch paginated accounts from the database

		accounts, total, totalPages, err := paginatedAccounts(db, c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching accounts"})
			return
		}

		// Prepare response data

		response := gin.H{
			"data":        accounts,
			"page":        c.Query("page"),
			"limit":       c.Query("limit"),
			"total":       total,
			"total_pages": totalPages,
		}

		// Cache the response data

		cacheInstance.Set(cacheKey, response, cache.DefaultExpiration)

		// Send response

		c.JSON(http.StatusOK, response)
	})

	///////////////////////////////////////////// LOGIN AND 2FA \\\\\\\\\\\ tried integrating login and 2fa here but failed.///////////////////

	r.POST("/login", func(c *gin.Context) {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TwoFA    string `json:"twofa"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Find the user by username
		var account Accounts
		err := db.Model(&account).Where("username = ?", input.Username).Select()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Validate password
		if err := bcrypt.CompareHashAndPassword(
			[]byte(account.EncryptedPassword),
			[]byte(input.Password+account.Salt),
		); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}

		// Validate 2FA code
		valid := totp.Validate(input.TwoFA, account.SecretKey2FA)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
			return
		}

		// Create a new session (optional)
		session := Session{
			SessionMetadata: input.Username,
			ExpiryDatetime:  time.Now().Add(30 * time.Minute),
		}
		_, err = db.Model(&session).Insert()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create session"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
	})

	////////////////////////////////// Endpoint to generate a 2FA secret
	r.POST("/generate-2fa", func(c *gin.Context) {
		var input struct {
			Username string `json:"username"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Find the user
		var account Accounts
		err := db.Model(&account).Where("username = ?", input.Username).Select()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Generate 2FA secret
		secret := totp.GenerateOpts{
			Issuer:      "WIRA",
			AccountName: account.Username,
		}
		otpKey, err := totp.Generate(secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate 2FA key"})
			return
		}

		// Save the secret key in the database
		account.SecretKey2FA = otpKey.Secret()
		_, err = db.Model(&account).Where("username = ?", account.Username).Update()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "2FA secret generated", "key": otpKey.URL()})
	})

	r.Run(":8080")
}

////////////////////////////////////////// CACHING END \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
