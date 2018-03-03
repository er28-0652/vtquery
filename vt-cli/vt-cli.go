package main

import (
	"log"
	"os"

	"github.com/er28-0652/vtquery"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

func query(c *cli.Context) error {
	vt, err := vtquery.NewDefaultClient()
	if err != nil {
		return err
	}
	query := c.String("query")
	var result vtquery.QueryResult

	switch {
	case vtquery.IsValidHash(query):
		result, err = vt.HashQuery(query)
	case vtquery.IsValidURL(query):
		result, err = vt.URLQuery(query)
	default:
		return errors.New("unknown query type")
	}

	if err != nil {
		return errors.Wrap(err, "fail to query VT")
	}
	result.ShowReport()
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
