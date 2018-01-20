package main

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/er28-0652/vtquery"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	// regexp for MD5, SHA1 and SHA256
	hashPtn = regexp.MustCompile(`(^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$)`)

	// regexp for URL pattern
	urlPtn = regexp.MustCompile(`^https?://.*`)
)

func query(c *cli.Context) error {
	vt := vtquery.DefaultClient()
	query := c.String("query")
	var result interface{}
	var err error

	switch {
	case hashPtn.MatchString(query):
		result, err = vt.HashQuery(query)
	case urlPtn.MatchString(query):
		result, err = vt.URLQuery(query)
	default:
		return errors.New("unknown query type")
	}

	if err != nil {
		return errors.Wrap(err, "fail to query VT")
	}
	fmt.Printf("%#v\n", result)
	return nil
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "query, q",
			Usage: "hash or url to query",
		},
	}
	app.Action = query

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	return
}
