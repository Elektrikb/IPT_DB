# IPT_DB

Регистрация пользователя в удалённой БД
![image](https://github.com/user-attachments/assets/3ff251c5-f0a5-4e44-813c-4b7409f8099e)

Авторизация под пользователем
![image](https://github.com/user-attachments/assets/0bd46cf3-5fd4-44a1-9c8f-6a98716e3c8c)

Вывод информации из БД
![image](https://github.com/user-attachments/assets/c8485d56-0814-479d-8bb4-0ec956140f83)


``` go

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string
	Password string
	Role     string
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
	Role string `json:"role"`
}

func generateToken(username string, role string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role, // Включаем роль в токен
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	// Проверяем имя пользователя и пароль
	storedPassword, ok := users[creds.Username]
	if !ok || storedPassword != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	// Извлекаем роль пользователя из мапы roles
	role, roleExists := roles[creds.Username]
	if !roleExists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "role not assigned"})
		return
	}

	// Генерация токена с ролью пользователя
	token, err := generateToken(creds.Username, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid token"})
				c.Abort() // Прерываем обработку запроса
				return
			}

			// Обработка истёкшего токена
			if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors == jwt.ValidationErrorExpired {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "token expired"})
				c.Abort()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		c.Next() // Если всё в порядке, передаём управление следующему обработчику
	}
}

var users = map[string]string{
	"admin":    "admin123",
	"user":     "password",
	"elektrik": "2003",
}

func register(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	// Проверка, существует ли пользователь
	if _, exists := users[creds.Username]; exists {
		c.JSON(http.StatusConflict, gin.H{"message": "user already exists"})
		return
	}

	// По умолчанию роль "user", можно добавить проверку или параметр для роли
	role := "user" // Устанавливаем роль по умолчанию как "user"

	// Можно добавить параметр для роли в запросе регистрации, например:
	if creds.Role != "" {
		role = creds.Role
	}

	// Регистрируем пользователя
	users[creds.Username] = creds.Password
	roles[creds.Username] = role // Сохраняем роль в мапе

	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}

var roles = map[string]string{
	"admin":    "admin",
	"user":     "user",
	"elektrik": "user",
}

func roleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		// Проверяем роль пользователя
		if claims.Role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func refresh(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	claims := &Claims{}

	// Парсим исходный токен
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
		return
	}

	// Проверяем, не истек ли срок действия токена
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		c.JSON(http.StatusBadRequest, gin.H{"message": "token not expired enough"})
		return
	}

	// Генерация нового токена с теми же данными (пользователь и роль), но с новым временем истечения
	newToken, err := generateToken(claims.Username, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

var db *gorm.DB

func initDB() {
	dsn := "host=213.171.10.112 user=postgres password=67 dbname=bookdb port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&Book{})
}

type Book struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

func main() {
	initDB()
	router := gin.Default()

	router.POST("/login", login)
	router.POST("/register", register)
	router.POST("/refresh", refresh)

	protected := router.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/books", getBooks)

		protected.GET("/products/:id", getBookByID)

		protected.POST("/books", roleMiddleware("admin"), createBook)

		protected.PUT("/books/:id", roleMiddleware("admin"), updateBook)

		protected.DELETE("/books/:id", roleMiddleware("admin"), deleteBook)

	}
	router.Run(":8080")
}

func getBooks(c *gin.Context) {
	var books []Book
	db.Find(&books)
	c.JSON(http.StatusOK, books)
}

func getBookByID(c *gin.Context) {
	id := c.Param("id")
	var book Book
	if err := db.First(&book, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "product not found"})
	}
	c.JSON(http.StatusOK, book)

}

func createBook(c *gin.Context) {
	var newBook Book

	if err := c.BindJSON(&newBook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	db.Create(&newBook)
	c.JSON(http.StatusCreated, newBook)

}

func updateBook(c *gin.Context) {
	id := c.Param("id")
	var updatedBook Book

	if err := c.BindJSON(&updatedBook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
		return
	}

	if err := db.Model(&Book{}).Where("id = ?", id).Updates(updatedBook).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "product not found"})
	}

	c.JSON(http.StatusOK, updatedBook)
}

func deleteBook(c *gin.Context) {
	id := c.Param("id")

	if err := db.Delete(&Book{}, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "product not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "product deleted"})

}


```
