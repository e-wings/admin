package src

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	. "github.com/beego/admin/src/lib"
	m "github.com/beego/admin/src/models"
)

//check access and register user's nodes
func AccessRegister() {
	var Check = func(ctx *context.Context) {
		user_auth_type, _ := strconv.Atoi(beego.AppConfig.String("user_auth_type"))
		rbac_auth_gateway := beego.AppConfig.String("rbac_auth_gateway")
		var accesslist map[string]bool
		if user_auth_type > 0 {
			params := strings.Split(strings.ToLower(ctx.Request.RequestURI), "/")
			if CheckAccess(params) {
				uinfo := ctx.Input.Session("userinfo")
				if uinfo == nil {
					ctx.Redirect(302, rbac_auth_gateway+"?ret="+ctx.Request.RequestURI)
				}
				//admin用户不用认证权限
				adminuser := beego.AppConfig.String("rbac_admin_user")
				if uinfo != nil {
					if uinfo.(m.User).Username == adminuser {
						return
					}
				}
				if user_auth_type == 1 {
					listbysession := ctx.Input.Session("accesslist")
					if listbysession != nil {
						accesslist = listbysession.(map[string]bool)
					}
				} else if user_auth_type == 2 {
					if uinfo != nil {
						accesslist, _ = GetAccessList(uinfo.(m.User).Id)
					}
				}

				ret := AccessDecision(params, accesslist)
				fmt.Println("accesslist=========>", accesslist, ret)
				if !ret {
					ctx.Output.JSON(&map[string]interface{}{"status": false, "info": "权限不足"}, true, false)
				}
			}

		}
	}
	//任何路由之前，都先执行Check
	beego.InsertFilter("/*", beego.BeforeRouter, Check)
}

//Determine whether need to verify
func CheckAccess(params []string) bool {
	// if len(params) < 3 {
	// 	return false
	// }
	for _, nap := range strings.Split(beego.AppConfig.String("not_auth_package"), ",") {
		if params[1] == nap {
			return false
		}
	}
	return true
}

//To test whether permissions
func AccessDecision(params []string, accesslist map[string]bool) bool {
	if CheckAccess(params) {
		var s string
		switch len(params) {
		case 1:
			return true
		case 2:
			s = fmt.Sprintf("%s", params[1])
		case 3:
			s = fmt.Sprintf("%s/%s", params[1], params[2])
		case 4:
			s = fmt.Sprintf("%s/%s/%s", params[1], params[2], params[3])
		}
		if len(accesslist) < 1 {
			return false
		}
		_, ok := accesslist[s]
		if ok != false {
			return true
		}
	} else {
		return true
	}
	return false
}

type AccessNode struct {
	Id        int64
	Name      string
	Childrens []*AccessNode
}

//Access permissions list
func GetAccessList(uid int64) (map[string]bool, error) {
	list, err := m.AccessList(uid)
	if err != nil {
		return nil, err
	}
	alist := make([]*AccessNode, 0)

	//读取顶级权限 pid==0，level==1；pid<- parent id
	for _, l := range list {
		if l["Pid"].(int64) == 0 && l["Level"].(int64) == 1 {
			anode := new(AccessNode)
			anode.Id = l["Id"].(int64)
			anode.Name = l["Name"].(string)
			alist = append(alist, anode)
		}
	}
	//读取第二级权限，读出后存入顶级权限的Childrens
	for _, l := range list { //第1层循环：所有权限
		if l["Level"].(int64) == 2 {
			for _, an := range alist { //第2层循环：顶级权限
				if an.Id == l["Pid"].(int64) {
					anode := new(AccessNode)
					anode.Id = l["Id"].(int64)
					anode.Name = l["Name"].(string)
					an.Childrens = append(an.Childrens, anode)
				}
			}
		}
	}
	//读取第三级权限，读出后存入第二级权限的Childrens
	for _, l := range list { //第1层循环：所有权限
		if l["Level"].(int64) == 3 {
			for _, an := range alist { //第2层循环：顶级权限
				for _, an1 := range an.Childrens { //第3层循环：第二级权限
					if an1.Id == l["Pid"].(int64) {
						anode := new(AccessNode)
						anode.Id = l["Id"].(int64)
						anode.Name = l["Name"].(string)
						an1.Childrens = append(an1.Childrens, anode)
					}
				}
			}
		}
	}
	accesslist := make(map[string]bool)
	for _, v := range alist { //第1层循环：顶级权限
		vname := strings.ToLower(strings.Split(v.Name, "/")[0])
		accesslist[vname] = true
		for _, v1 := range v.Childrens { //第2层循环：第二级权限
			fmt.Println("  v1.Childrens=", v1.Childrens, v.Name, v1.Name)
			v1name := strings.ToLower(strings.Split(v1.Name, "/")[0])
			accesslist[vname+"/"+v1name] = true
			for _, v2 := range v1.Childrens { //第3层循环：第三级权限
				v2name := strings.ToLower(strings.Split(v2.Name, "/")[0])
				str := fmt.Sprintf("%s/%s/%s", vname, v1name, v2name[0])
				accesslist[str] = true
			}
		}
	}
	return accesslist, nil
}

//check login
func CheckLogin(username string, password string) (user m.User, err error) {
	user = m.GetUserByUsername(username)
	if user.Id == 0 {
		return user, errors.New("用户不存在")
	}
	if user.Password != Pwdhash(password) {
		return user, errors.New("密码错误")
	}
	return user, nil
}
