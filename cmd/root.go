/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"git.lyonsoftworks.com/jlyon1/auth-proxy-gate/internal/transport"
	bolt "go.etcd.io/bbolt"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth-proxy-gate",
	Short: "",
	Long:  ``,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		host := viper.GetString("host")
		port := viper.GetInt32("port")
		secure := viper.GetBool("secure")

		secret := viper.GetString("secret")
		redirect := viper.GetString("redirect")
		clientID := viper.GetString("clientid")
		secretKey := viper.GetString("secretKey")

		proxy := viper.GetString("proxy")

		logger, _ := zap.NewDevelopment()
		log := logger.Sugar()

		db, err := bolt.Open("./sessions.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.Error("error creating bolt db", err)
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

			DB: *db,
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
}
