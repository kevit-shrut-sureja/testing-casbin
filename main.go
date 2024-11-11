package main

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const Casbinmodel = `
[request_definition]
r = user, tenant, feature, action, resource_attr

[policy_definition]
p = role, tenant, feature, action, resource_attr, eft

[role_definition]
g = _, _, _ 
# user, tenant, feature

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (g(r.user, p.role, r.tenant) || g(r.user, p.role, "all")) && \
    (r.tenant == p.tenant || p.tenant == "*") && \
    (r.feature == p.feature || p.feature == "*") && \
    (r.action == p.action || p.action == "*") && \
    (r.resource_attr == p.resource_attr || p.resource_attr == "*")
`

type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:512;uniqueIndex:unique_index"`
	V0    string `gorm:"size:512;uniqueIndex:unique_index"`
	V1    string `gorm:"size:512;uniqueIndex:unique_index"`
	V2    string `gorm:"size:512;uniqueIndex:unique_index"`
	V3    string `gorm:"size:512;uniqueIndex:unique_index"`
	V4    string `gorm:"size:512;uniqueIndex:unique_index"`
	V5    string `gorm:"size:512;uniqueIndex:unique_index"`
	V6    string `gorm:"size:512;uniqueIndex:unique_index"`
}

func main() {
	db, err := gorm.Open(postgres.Open("host=localhost dbname=crm port=5431 sslmode=disable user=postgres password=postgres"), &gorm.Config{})
	if err != nil {
		fmt.Println(err)
	}
	a, _ := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	m, _ := model.NewModelFromString(Casbinmodel)
	e, _ := casbin.NewEnforcer(m, a)

	e.LoadPolicy()

	e.AddPolicy("p", "admin", "*")

	fmt.Println(e)
}
