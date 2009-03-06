/**
 * Contains most of the domain admin functions
 */

ZaDelegatedAdmin = function () {};

if (ZaAccount) {
    ZaAccount.A_zimbraIsAdminAccount = "zimbraIsAdminAccount" ;
    ZaAccount.myXModel.items.push (
        {id:ZaAccount.A_zimbraIsAdminAccount, type:_ENUM_, choices:ZaModel.BOOLEAN_CHOICES,
            ref:"attrs/"+ZaAccount.A_zimbraIsAdminAccount}) ;

    //admin roles model item
      ZaAccount.A2_adminRoles = "adminRoles" ;
      var adminRolesModelItem = {ref: ZaAccount.A2_adminRoles ,id: ZaAccount.A2_adminRoles,
                                type: _LIST_, listItem:{type:_EMAIL_ADDRESS_}} ;
      ZaAccount.myXModel.items.push (adminRolesModelItem) ;


    ZaAccount.changeAdminRoles = function (value, event, form) {
        var oldVal = this.getInstanceValue();
        if(oldVal == value)
            return;

        this.setInstanceValue(value);

         //add this value to the  direct member
        var directMemberOfList = this.getInstance () [ZaAccount.A2_memberOf] [ZaAccount.A2_directMemberList] ;
        if (ZaUtil.findValueInObjArrByPropertyName(directMemberOfList, value, "name") < 0){
            directMemberOfList.push ({
                id: this.getChoices().getChoiceByValue(value).id,
                name: value
            }) ;
       
            form.getModel().setInstanceValue(this.getInstance(), ZaAccount.A2_directMemberList, directMemberOfList) ;
        }
    }

    ZaAccount.onAdminRoleRemove = function (index, form) {
        var value = this.getInstanceValue () [index] ;
        var path = this.getRefPath();
		this.getModel().removeRow(this.getInstance(), path, index);
        this.items[index].clearError();

        //update the memberOf instance value
        var directMemberOfList = this.getInstance () [ZaAccount.A2_memberOf] [ZaAccount.A2_directMemberList] ;
        var i = ZaUtil.findValueInObjArrByPropertyName(directMemberOfList, value, "name")  ; 
        if (i >= 0){
            directMemberOfList.splice (i, 1) ;
            form.getModel().setInstanceValue(this.getInstance(), ZaAccount.A2_directMemberList, directMemberOfList) ;
            form.parent.setDirty (true) ;
        }
    }

    ZaAccount.getAdminChkBoxItem = function () {
        var adminChkBox = {
            ref:ZaAccount.A_zimbraIsAdminAccount,type:_CHECKBOX_,
            label:ZaMsg.NAD_IsAdmin,
            bmolsnr:true,
            elementChanged :
            function(elementValue,instanceValue, event) {
                if(elementValue == "TRUE") {
                    this.setInstanceValue("FALSE", ZaAccount.A_zimbraIsSystemAdminAccount);
                }
                    this.getForm().itemChanged(this, elementValue, event);
            },
            trueValue:"TRUE", falseValue:"FALSE"
        };

        return adminChkBox;
    }

    ZaAccount.getAdminRolesItem = function () {
       var adminRoleField = {
            ref: ".", type: _DYNSELECT_ ,
            dataFetcherMethod:ZaSearch.prototype.dynSelectSearchAdminGroups,
            onChange: ZaAccount.changeAdminRoles ,
            emptyText:com_zimbra_delegatedadmin.searchTermAdminGroup,
            dataFetcherClass:ZaSearch,editable:true
       }

       var adminRolesItem = {
           ref: ZaAccount.A2_adminRoles , type: _REPEAT_,
           label: com_zimbra_delegatedadmin.Label_AssignAdminRole, labelLocation:_LEFT_ ,
           labelCssStyle:"vertical-align: top; padding-top: 3px;",
           align:_LEFT_,
           repeatInstance:"",
           showAddButton:true, showAddOnNextRow:true, addButtonWidth: 50, addButtonLabel:com_zimbra_delegatedadmin.NAD_Add,
           showRemoveButton:true , removeButtonWidth: 50, removeButtonLabel:com_zimbra_delegatedadmin.NAD_Remove,
           visibilityChecks:["instance.attrs[ZaAccount.A_zimbraIsAdminAccount]==\'TRUE\' "],
           visibilityChangeEventSources: [ZaAccount.A_zimbraIsAdminAccount] ,
           onRemove:ZaAccount.onAdminRoleRemove,
           items:[adminRoleField]
       }

        return adminRolesItem ;

    }
}

ZaDelegatedAdmin.accountObjectModifer = function () {
    var directMemberOfList = this._containedObject [ZaAccount.A2_memberOf] [ZaAccount.A2_directMemberList] ;
    if (! this._containedObject [ZaAccount.A2_adminRoles]) this._containedObject [ZaAccount.A2_adminRoles] = [];
    
    for (var i = 0; i < directMemberOfList.length; i ++) {
    // TODO: enable it when GetAccountMembershipRequest returns isAdminGroup
                //            if (directMemberOfList[i][ZaDistributionList.A_isAdminGroup] == "TRUE")
                    this._containedObject [ZaAccount.A2_adminRoles].push (directMemberOfList[i].name) ;
            }
}

if (ZaTabView.ObjectModifiers["ZaAccountXFormView"]){
    ZaTabView.ObjectModifiers["ZaAccountXFormView"].push(ZaDelegatedAdmin.accountObjectModifer) ;
}


if (ZaTabView.XFormModifiers["ZaAccountXFormView"]) {
   ZaDelegatedAdmin.AccountXFormModifier = function (xFormObject) {
       var adminChkBox = ZaAccount.getAdminChkBoxItem ();
       var adminRolesItem = ZaAccount.getAdminRolesItem () ;

        var tabs = xFormObject.items[2].items;
        var tmpItems = tabs[0].items;
        var cnt = tmpItems.length;
        for(var i = 0; i < cnt; i ++) {
           if(tmpItems[i].id == "account_form_setup_group" && tmpItems[i].items) {
               var tmpGrouperItems = tmpItems[i].items;
               var cnt2 = tmpGrouperItems.length;
               for(var j=0;j<cnt2;j++) {
                   if(tmpGrouperItems[j] && tmpGrouperItems[j].ref == ZaAccount.A_zimbraIsSystemAdminAccount) {
                       //add  Admin checkbox
                       xFormObject.items[2].items[0].items[i].items.splice(j+1,0, adminChkBox, adminRolesItem);
                       
                       //add the mutual exclusive action to global admin 
                       tmpGrouperItems[j].elementChanged =
								function(elementValue,instanceValue, event) {
									if(elementValue == "TRUE") {
										this.setInstanceValue("FALSE", ZaAccount.A_zimbraIsAdminAccount);
								    }
										this.getForm().itemChanged(this, elementValue, event);
								};
                       break;
                   }
               }
               break;
           }
       }
   }

    ZaTabView.XFormModifiers["ZaAccountXFormView"].push(ZaDelegatedAdmin.AccountXFormModifier);
}


ZaDelegatedAdmin.accountViewMethod =
function (entry) {
    if (entry.attrs[ZaAccount.A_zimbraIsAdminAccount]
            && entry.attrs[ZaAccount.A_zimbraIsAdminAccount] == "TRUE" ) {
        this._view._containedObject[ZaAccount.A2_adminRoles] = [] ;
        //Get the isAdminAccount DLs from the directMemberList
        var allDirectMemberOfs = this._view._containedObject [ZaAccount.A2_memberOf] [ZaAccount.A2_directMemberList] ;
        for (var i = 0; i < allDirectMemberOfs.length; i ++) {
// TODO: enable it when GetAccountMembershipRequest returns isAdminGroup
            //            if (allDirectMemberOfs[i][ZaDistributionList.A_isAdminGroup] == "TRUE")
                this._view._containedObject[ZaAccount.A2_adminRoles].push (allDirectMemberOfs[i].name) ;
        }

        var xform = this._view._localXForm ;
        var instance  = xform.getInstance ();
        xform.getModel().setInstanceValue(instance,ZaAccount.A2_adminRoles,
                 this._view._containedObject[ZaAccount.A2_adminRoles]);
    }
}

if (ZaController.setViewMethods["ZaAccountViewController"]) {
	ZaController.setViewMethods["ZaAccountViewController"].push(ZaDelegatedAdmin.accountViewMethod);
}

if (ZaDistributionList) {
    ZaDistributionList.A_isAdminGroup = "zimbraIsAdminGroup" ;
    ZaDistributionList.myXModel.items.push (
        {id:ZaDistributionList.A_isAdminGroup, type:_ENUM_, choices:ZaModel.BOOLEAN_CHOICES,
            ref:"attrs/"+ZaDistributionList.A_isAdminGroup}) ;
}


if (ZaTabView.XFormModifiers["ZaDLXFormView"]) {
   ZaDelegatedAdmin.DLXFormModifier = function (xFormObject) {
       /*this item is to be added in the permission view
            var adminGroupChkBx =
                {type:_GROUP_, numCols:2,colSpan: "*", colSizes:["20px","*"],
                    cssStyle:"margin-top:10px;margin-left: 10px; margin-right:auto;",
                    items: [
                        {
                            ref: ZaDistributionList.A_isAdminGroup,type:_CHECKBOX_,
                            label:com_zimbra_delegatedadmin.NAD_IsAdminGroup,
                            enableDisableChecks:[],
                            visibilityChecks:[],
                            trueValue:"TRUE", falseValue:"FALSE"
                        }
                    ]
                }; */
       var adminGroupChkBx =
            {
                ref: ZaDistributionList.A_isAdminGroup,type:_CHECKBOX_,
                label:com_zimbra_delegatedadmin.NAD_IsAdminGroup + ": ",
                labelLocation:_LEFT_,  align:_LEFT_,
				labelCssClass:"xform_label", cssStyle:"padding-left:0px",
                enableDisableChecks:[],
                visibilityChecks:[],
                trueValue:"TRUE", falseValue:"FALSE"
            }  ;
       
       var switchGroupItems ;
        for (var i=0; i < xFormObject.items.length; i ++) {
            if (xFormObject.items[i].type == _SWITCH_) {
                switchGroupItems = xFormObject.items[i].items ;
                break ;
            }
        }

        var membersView, tmpGroup;
        for (var j=0; j < switchGroupItems.length; j ++) {
            if ((switchGroupItems[j].type == _ZATABCASE_ )
                    && (switchGroupItems[j].id == "dl_form_members")) {
                membersView = switchGroupItems[j].items[0].items ;
                for (var m=0; m < membersView.length; m ++) {
                    if (membersView[m].id == "dl_form_members_general_group") {
                        for (var n=0; n < membersView[m].items.length; n ++ ) {
                            if (membersView[m].items[n].ref == "zimbraMailStatus") {
                                membersView[m].items.splice (n,0, adminGroupChkBx) ;
                                break;
                            }
                        }
                        break ;
                    }
                }
                break ;
            }
        }

//        permissionView.items.splice(0, 0, adminGroupChkBx);
   }

   ZaTabView.XFormModifiers["ZaDLXFormView"].push(ZaDelegatedAdmin.DLXFormModifier);

}

if (ZaSearch) {
    ZaSearch.prototype.dynSelectSearchAdminGroups =  function (value, event, callback) {
        var extraLdapQuery = "(zimbraIsAdminGroup=TRUE)" ;
        ZaSearch.prototype.dynSelectSearchGroups.call (this, value, event, callback, extraLdapQuery) ;
    }
}






