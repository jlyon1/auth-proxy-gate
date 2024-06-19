/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/auth"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/transport"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type AppConfig struct {
	AuthenticatorConfig auth.AuthenticatorConfig `json:"AuthenticatorConfig"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth-proxy-gate",
	Short: "",
	Long:  ``,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		var cfg AppConfig

		err := viper.ReadInConfig()
		if err != nil {
			panic("config not found") //TODO fix error handling here
		}

		err = viper.Unmarshal(&cfg)
		if err != nil {
			panic(err)
		}

		fmt.Println(cfg)

		host := viper.GetString("host")
		port := viper.GetInt32("port")
		secure := viper.GetBool("secure")

		secret := viper.GetString("secret")
		redirect := viper.GetString("redirect")
		clientID := viper.GetString("clientid")
		secretKey := viper.GetString("secretKey")
		allowList := viper.GetString("allowList")

		list := strings.Split(allowList, ",")

		proxy := viper.GetString("proxy")

		logger, _ := zap.NewDevelopment()
		log := logger.Sugar()

		if len(list) == 0 {
			log.Warn("list is empty, all users allowed")
		}

		db, err := sql.Open("sqlite3", "./accounts.db")
		if err != nil {
			panic(err)
		}

		defer db.Close()

		defer func() {
			log.Info("Graceful shutdown complete")
		}()

		api := transport.Http{
			ListenURL:    fmt.Sprintf("%s:%d", host, port),
			Secure:       secure,
			RedirectURI:  redirect,
			ClientSecret: secret,
			ClientID:     clientID,
			Proxy:        proxy,
			SecretKey:    secretKey,
			AllowList:    list,
			Authenticator: &auth.Authenticator{
				DB: db,
			},

			DB: db,
		}
		wg := sync.WaitGroup{}

		ctx, cancel := context.WithCancel(context.Background())

		wg.Add(1)
		go func() {
			err = api.ListenAndServe(log, ctx)

			if err != nil {
				log.Error(err)
			}

			wg.Done()

		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Info("Shutdown called... stopping")
		cancel()

		wg.Wait()

		log.Info("done")

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.auth-proxy-gate.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().String("host", "0.0.0.0", "Host to listen on")
	viper.BindPFlag("host", rootCmd.Flags().Lookup("host"))

	rootCmd.Flags().Int32("port", 8081, "port to listen on")
	viper.BindPFlag("port", rootCmd.Flags().Lookup("port"))

	rootCmd.Flags().Bool("secure", false, "secure")
	viper.BindPFlag("secure", rootCmd.Flags().Lookup("secure"))

	rootCmd.Flags().String("secret", "", "Client Secret")
	viper.BindPFlag("secret", rootCmd.Flags().Lookup("secret"))

	rootCmd.Flags().String("redirect", "", "Redirect")
	viper.BindPFlag("redirect", rootCmd.Flags().Lookup("redirect"))

	rootCmd.Flags().String("clientid", "", "Client ID")
	viper.BindPFlag("clientid", rootCmd.Flags().Lookup("clientid"))

	rootCmd.Flags().String("proxy", "", "Proxy URL")
	viper.BindPFlag("proxy", rootCmd.Flags().Lookup("proxy"))

	rootCmd.Flags().String("secretKey", "", "Secret Key")
	viper.BindPFlag("secretKey", rootCmd.Flags().Lookup("secretKey"))

	rootCmd.Flags().String("allowList", "", "Allow List")
	viper.BindPFlag("allowList", rootCmd.Flags().Lookup("allowList"))

	viper.AddConfigPath(".")
	viper.SetConfigFile("config.json")
}
