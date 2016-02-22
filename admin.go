package admin

import (
	"fmt"
	"mime"
	"os"

	"github.com/astaxie/beego"
	. "github.com/beego/admin/src/lib"
	"github.com/beego/admin/src/models"
)

const VERSION = "0.1.1"

func Run() {
	//初始化
	initialize()

	fmt.Println("Starting....")

	fmt.Println("Start ok")
}
func initialize() {
	mime.AddExtensionType(".css", "text/css")
	//判断初始化参数
	initArgs()
	//连接数据库
	models.Connect()
	//初始化路由
	router()
	beego.AddFuncMap("stringsToJson", StringsToJson)
}
func initArgs() {
	args := os.Args
	for _, v := range args {
		if v == "-syncdb" {
			models.Syncdb()
			os.Exit(0)
		}
	}
}
