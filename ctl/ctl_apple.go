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

// Verify that the specified certificate is included in the CTL or has been removed
func (ctl *AppleCTL) Verify(certs []*Cert, allowedCerts Entrys) *VerifyResult {
	ret := VerifyResult{
		Total:        len(certs),
		TrustedCerts: []*Cert{},
		AllowedCerts: []*Cert{},
		allowedDesc:  "Allow by yourself in the config file.\n",
		RemovedCerts: []*Cert{},
		removedDesc:  "See https://support.apple.com/en-us/HT209143\n",
		UnknownCerts: []*Cert{},
		unknownDesc:  "",
	}
	ctl.verify(certs, allowedCerts, &ret)
	return &ret
}

func (ctl *AppleCTL) Fetch() error {
	doc, err := htmlquery.LoadURL(AppleKBURL)
	if err != nil {
		return err
	}
	nodeDate := htmlquery.FindOne(doc, "//span[text()='Published Date:']/following-sibling::time")
	if nodeDate == nil {
		return fmt.Errorf("can not find apple publish date")
	}
	date := htmlquery.InnerText(nodeDate)
	_, err = parseDate(date)
	if err != nil {
		return fmt.Errorf("can not parse apple publish date: %w", err)
	}
	if strings.Compare(date, ctl.PublishedDate) < 1 {
		return nil // no update
	}
	ctl.PublishedDate = date
	nodeLink := htmlquery.FindOne(doc, "//h2[text()='Current Trust Store']/following-sibling::*//a")
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
	xpathTrusted := "//h2[@id='trusted' or text()='Trusted Certificates' or text()='Trusted certificates']/following-sibling::div[1]//table"
	rows := parseTable(page, fmt.Sprintf("%s//th", xpathTrusted), fmt.Sprintf("%s//tr[position()>1]", xpathTrusted))
	ctl.Trusted = extractEntrys(rows)
	if len(ctl.Trusted) == 0 {
		return fmt.Errorf("can not find data table in the page")
	}
	xpathBlocked := "//h2[@id='blocked' or text()='Blocked Certificates' or text()='Blocked certificates']/following-sibling::div[1]//table"
	rows = parseTable(page, fmt.Sprintf("%s//th", xpathBlocked), fmt.Sprintf("%s//tr[position()>1]", xpathBlocked))
	ctl.Removed = extractEntrys(rows)
	ctl.UpdatedAt = time.Now()
	return nil
}

func extractEntrys(rows []map[string]string) Entrys {
	entrys := Entrys{}
	fpKey := strings.ToUpper("Fingerprint (SHA-256)")
	certNameKey := strings.ToUpper("Certificate name")
	for _, v := range rows {
		fingerprint := strings.ToUpper(strings.ReplaceAll(v[fpKey], " ", ""))
		if fingerprint != "" {
			entrys[fingerprint] = v[certNameKey]
		}
	}
	return entrys
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
		headers = append(headers, strings.ToUpper(strings.TrimSpace(htmlquery.InnerText(v))))
	}
	for _, v := range trNodes {
		row := map[string]string{}
		for m, n := range headers {
			text := htmlquery.Find(v, fmt.Sprintf(`./td[%d]//text()`, m+1))
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
