package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TorExitNode represents the model for Tor exit-node information
type TorExitNode struct {
	ID        uint   `gorm:"primaryKey"`
	IPAddress string `gorm:"unique"`
	Country   string
	Timestamp time.Time
}

// (dis)allow list structure
type Allowlist struct {
	ID        uint   `gorm:"primaryKey"`
	IPAddress string `gorm:"unique"`
}

var db *gorm.DB
var torExitNodes []TorExitNode

func main() {
	r := gin.Default()

	initDatabase()
	go fetchTorExitNodesPeriodically()

	// API endpoints to get and modify the allow list
	r.POST("/allowlist", addToAllowlist)
	r.DELETE("/allowlist", removeFromAllowlist)
	r.GET("/allowlist", getAllowlist)

	// API endpoint for aggregated list of exit node addresses
	r.GET("/tor-exit-nodes", getTorExitNodes)

	r.Run(":8080")
}

func addToAllowlist(c *gin.Context) {
	// Bind JSON request body to struct
	var req struct {
		IPAddresses []string `json:"ip_addresses"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, ip := range req.IPAddresses {
		var existingEntry Allowlist
		result := db.Where("ip_address = ?", ip).First(&existingEntry)
		// Make sure the address isn't already there before adding
		if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
			allowlistEntry := Allowlist{IPAddress: ip}
			db.Create(&allowlistEntry)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "IP addresses added to the allowlist"})
}

func removeFromAllowlist(c *gin.Context) {
	// Bind JSON request body to struct
	var req struct {
		IPAddresses []string `json:"ip_addresses"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, ip := range req.IPAddresses {
		var existingEntry Allowlist
		result := db.Where("ip_address = ?", ip).First(&existingEntry)
		// Make sure the address is there before removing
		if result.Error == nil {
			db.Delete(&existingEntry)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "IP addresses removed from the allowlist"})
}

func getAllowlist(c *gin.Context) {
	var entries []Allowlist
	db.Find(&entries)
	ipAddresses := make([]string, len(entries))
	for i, entry := range entries {
		ipAddresses[i] = entry.IPAddress
	}
	c.JSON(http.StatusOK, gin.H{"allowlist": ipAddresses})
}

func initDatabase() {
	// Open a SQLite database connection
	database, err := gorm.Open(sqlite.Open("tor_exit_nodes.db"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}
	// Auto-migrate both models
	database.AutoMigrate(&TorExitNode{}, &Allowlist{})
	// Our global db variable is called db
	db = database
}

func fetchTorExitNodesPeriodically() {
	// Our source says every half hour but let's do every hour to be safe
	ticker := time.NewTicker(1 * time.Hour)
	// Initial fetch on startup
	fetchTorExitNodes()
	for range ticker.C {
		fetchTorExitNodes()
	}
}

func fetchTorExitNodes() {
	// Fetch Tor exit-node IPs from the source URL
	url := "https://www.dan.me.uk/torlist/?exit"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching Tor exit nodes:", err)
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	var ips []string
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}
	saveToDatabase(ips)

}

func saveToDatabase(ips []string) {
	// Takes in an array of ip addresses and saves them to the database
	// Since we get all these nodes at the same time, we want to make sure they have the same timestamp
	currentTime := time.Now()
	for _, ip := range ips {
		var existingNode TorExitNode
		result := db.Where("ip_address = ?", ip).First(&existingNode)

		// If the IP doesn't already exist, create a new record
		if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
			country, err := getCountryFromIP(ip)
			if err != nil {
				fmt.Printf("Error getting country for IP %s: %v\n", ip, err)
				continue
			}

			// Trim the country string otherwise it shows up as "US\n" instead of "US"
			country = strings.TrimSpace(country)
			node := TorExitNode{
				IPAddress: ip,
				Country:   country,
				Timestamp: currentTime,
			}
			db.Create(&node)
		}
	}
}

func getCountryFromIP(ip string) (string, error) {
	// Query ipinfo.io API for country information
	// TODO: Find a different way to do this, ipinfo complains about too many requests
	url := fmt.Sprintf("https://ipinfo.io/%s/country", ip)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	country, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(country), nil
}

func getTorExitNodes(c *gin.Context) {
	// Allow for the following query parameters:
	// Select addresses from a certain country
	// Select addresses that were retrieved in a certain time range
	// Select {count} IPs at a time
	// Example:
	// http://localhost:8080/tor-exit-nodes?country=US&starttime=2024-02-12T00:00:00Z&endtime=2024-02-13T00:00:00Z&count=10
	country := c.Query("country")
	timeAddedStart := c.Query("starttime")
	timeAddedEnd := c.Query("endtime")
	pagination := c.Query("count")

	// Before accounting for parameters, we throw out everything in the (dis)allowlist
	query := db.Not("ip_address IN (?)", db.Table("allowlists").Select("ip_address"))
	if country != "" {
		query = query.Where("country = ?", country)
	}
	if timeAddedStart != "" {
		startTime, err := time.Parse(time.RFC3339, timeAddedStart)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid starttime format"})
			return
		}
		query = query.Where("timestamp > ?", startTime)
	}
	if timeAddedEnd != "" {
		endTime, err := time.Parse(time.RFC3339, timeAddedEnd)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endtime format"})
			return
		}
		query = query.Where("timestamp < ?", endTime)
	}

	var nodes []TorExitNode
	query.Find(&nodes)

	var paginationInt int
	if pagination != "" {
		var err error
		paginationInt, err = strconv.Atoi(pagination)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid pagination parameter"})
			return
		}
		nodes = nodes[:min(paginationInt, len(nodes))]
	}

	c.JSON(http.StatusOK, gin.H{"tor_exit_nodes": nodes})
}
