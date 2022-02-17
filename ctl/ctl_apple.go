package ctl

import (
	"fmt"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"
)

const AppleKBURL = "https://support.apple.com/en-us/HT209143"

type AppleCTL struct {
	*CTL          `yaml:",inline"`
	PublishURL    string `yaml:"publish_url,omitempty"`
	PublishedDate string `yaml:"published_date,omitempty"`
}

func NewAppleCTL() *AppleCTL {
	return &AppleCTL{
		CTL:           NewCTL(),
		PublishURL:    AppleKBURL,
		PublishedDate: "2006-01-02",
	}
}

func (ctl *AppleCTL) FetchApple() error {
	doc, err := htmlquery.LoadURL(AppleKBURL)
	if err != nil {
		return err
	}
	nodeDate := htmlquery.FindOne(doc, "//span[text()='Published Date:']/following-sibling::time")
	if nodeDate == nil {
		return fmt.Errorf("can not find apple publish date")
	}
	date := htmlquery.SelectAttr(nodeDate, "datetime")
	_, err = time.Parse("2006-01-02", date)
	if err != nil {
		return fmt.Errorf("can not parse apple publish date: %w", err)
	}
	if strings.Compare(date, ctl.PublishedDate) < 1 {
		return nil // no update
	}
	ctl.PublishedDate = date
	nodeLink := htmlquery.FindOne(doc, "//h2[text()='Current Trust Store']/following-sibling::div/p/a")
	if nodeLink == nil {
		return fmt.Errorf("can not find apple publish link")
	}
	link := htmlquery.SelectAttr(nodeLink, "href") // link to latest url
	return ctl.fetchData(link)
}

func (ctl *AppleCTL) fetchData(link string) error {
	page, err := htmlquery.LoadURL(link)
	if err != nil {
		return err
	}
	rows := parseTable(page, "//h2[@id='trusted']/following-sibling::div//table//th", "//h2[@id='trusted']/following-sibling::div//table//tr[position()>1]")
	ctl.Trusted = extractItems(rows)
	if len(ctl.Trusted) == 0 {
		return fmt.Errorf("can not find data table in the page")
	}
	rows = parseTable(page, "//h2[@id='blocked']/following-sibling::div//table//th", "//h2[@id='blocked']/following-sibling::div//table//tr[position()>1]")
	ctl.Removed = extractItems(rows)
	ctl.UpdatedAt = time.Now()
	return nil
}

func extractItems(rows []map[string]string) Items {
	items := Items{}
	for _, v := range rows {
		fingerprint := strings.ToUpper(strings.ReplaceAll(v["Fingerprint (SHA-256)"], " ", ""))
		if fingerprint != "" {
			items[fingerprint] = v["Certificate name"]
		}
	}
	return items
}

func parseTable(top *html.Node, thExpr, trExpr string) []map[string]string {
	data := []map[string]string{}
	thNodes := htmlquery.Find(top, thExpr)
	trNodes := htmlquery.Find(top, trExpr)
	if len(thNodes) == 0 || len(trNodes) == 0 {
		return data // empty
	}
	headers := []string{}
	for _, v := range thNodes {
		headers = append(headers, strings.TrimSpace(htmlquery.InnerText(v)))
	}
	for _, v := range trNodes {
		row := map[string]string{}
		for m, n := range headers {
			text := htmlquery.Find(v, fmt.Sprintf(`./td[%d]//*/text()`, m+1))
			value := ""
			for _, s := range text {
				value = value + " " + strings.TrimSpace(s.Data)
			}
			row[n] = strings.TrimSpace(value)
		}
		data = append(data, row)
	}
	return data
}
