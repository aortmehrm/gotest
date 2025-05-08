package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var jwtSecret = []byte("your-secret-key") // 💡 실제 배포에선 env로 분리
func generateToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // 24시간 유효
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Email    string `json:"email" gorm:"unique"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type PostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type Post struct {
	ID      uint   `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Author  string `json:"author"`
}

var postList []Post

func hashPassword(pw string) string {
	hash := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(hash[:])
}

func extractEmailFromToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("토큰 없음")
	}

	// "Bearer ~~~" 형식 → 실제 토큰만 추출
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("토큰 파싱 실패")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("claims 파싱 실패")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return "", fmt.Errorf("email claim 없음")
	}

	return email, nil
}

var DB *gorm.DB

func initDatabase() {
	var err error
	DB, err = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		panic("DB 연결 실패: " + err.Error())
	}

	// 테이블 자동 생성
	DB.AutoMigrate(&User{}) // ✅ 이 줄 추가
	DB.AutoMigrate(&Post{})
}

func main() {

	initDatabase() // 💡 DB 초기화 호출!

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	r.POST("/signup", func(c *gin.Context) {
		var user User

		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식 오류"})
			return
		}

		// 이메일 중복 체크
		var existing User
		if err := DB.Where("email = ?", user.Email).First(&existing).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "이미 가입된 아이디입니다"})
			return
		}

		// 비밀번호 해싱
		user.Password = hashPassword(user.Password)

		// DB 저장
		if err := DB.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "DB 저장 실패"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "회원가입 성공"})
	})

	r.POST("/login", func(c *gin.Context) {
		var loginData User

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식 오류"})
			return
		}

		// 사용자 조회
		var user User
		if err := DB.Where("email = ?", loginData.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "존재하지 않는 계정"})
			return
		}

		// 비밀번호 비교
		if user.Password != hashPassword(loginData.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "비밀번호 불일치"})
			return
		}

		// 토큰 생성
		token, err := generateToken(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	r.POST("/posts", func(c *gin.Context) {
		var post Post

		if err := c.ShouldBindJSON(&post); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식 오류"})
			return
		}

		// ✅ 토큰에서 이메일 추출 → 작성자 저장
		email, err := extractEmailFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "인증 실패: " + err.Error()})
			return
		}

		post.Author = email

		// DB 저장
		if err := DB.Create(&post).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "글 저장 실패"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "글 작성 성공"})
	})

	r.GET("/posts", func(c *gin.Context) {
		var posts []Post

		// 🔄 최신순으로 정렬
		if err := DB.Order("id desc").Find(&posts).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "DB 조회 실패"})
			return
		}

		c.JSON(http.StatusOK, posts)
	})

	r.PUT("/posts/:id", func(c *gin.Context) {
		id := c.Param("id")
		var updated Post

		if err := c.ShouldBindJSON(&updated); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "요청 형식 오류"})
			return
		}

		// 글 존재 확인 후 수정
		if err := DB.Model(&Post{}).Where("id = ?", id).
			Updates(Post{Title: updated.Title, Content: updated.Content}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "수정 실패"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	})

	r.DELETE("/posts/:id", func(c *gin.Context) {
		id := c.Param("id")

		if err := DB.Delete(&Post{}, id).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "삭제 실패"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	})

	r.Run(":8080")
}
