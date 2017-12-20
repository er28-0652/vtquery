package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/urfave/cli"
)http.ListenAndServe(":8080", nil)

func checkQueryType(query string) string {
	hashPtn := regexp.MustCompile(`(^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$)`)
	urlPtn := regexp.MustCompile(`^https?://.*`)
	if hashPtn.MatchString(query) == true {
		return "hash"
	} else if urlPtn.MatchString(query) == true {
		return "url"
	} else {
		return ""
	}
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "query, q",
			Usage: "hash or url to query",
		},
	}

	app.Action = func(c *cli.Context) error {
		vt := DefaultClient()
		q := c.String("query")
		t := checkQueryType(q)

		var result interface{}
		var err error
		if t == "hash" {
			result, err = vt.HashQuery(q)
			if err != nil {
				return err
			}
		} else if t == "url" {
			result, err = vt.URLQuery(q)
			if err != nil {
				return err
			}
		}
		fmt.Printf("%+v\n", result)
		return nil
	}
	app.Run(os.Args)
	return
}
