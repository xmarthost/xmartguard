<?php

namespace XMartHost\Mcp;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

/**
 * Every WHMCS API action with its permission category, the access level a
 * connector needs to run it, and the main parameters (the AI reads these
 * through whmcs_find_actions before calling whmcs_api_call).
 *
 * Access levels:
 *   r  read       - reads data only
 *   w  write      - creates or changes data
 *   f  full       - deletes data, terminates services, reveals secrets or
 *                    changes system configuration
 *
 * Actions not listed here (added by newer WHMCS releases) can still be run
 * with whmcs_api_call by a Full access connector.
 */
class Catalog
{
    const CATEGORIES = [
        'Clients' => 'Clients, contacts, users and affiliates',
        'Billing' => 'Invoices, payments, credit, quotes and transactions',
        'Orders' => 'Orders and promotions',
        'Products' => 'Products, product groups, configurable options and addons',
        'Services' => 'Hosting services, addons, provisioning (create, suspend, terminate)',
        'Domains' => 'Domains, registrars, TLD pricing, WHOIS',
        'Support' => 'Tickets, departments, announcements, client notes',
        'Reports' => 'MRR, churn, revenue, top clients, aging invoices',
        'Projects' => 'Project Management addon',
        'System' => 'Admins, email templates, settings, modules, servers, logs, SSO',
    ];

    const LEVELS = ['r' => 1, 'w' => 2, 'f' => 3];
    const SCOPES = ['read' => 1, 'write' => 2, 'full' => 3];

    /** action => [category, access, parameters] */
    const ACTIONS = [
        // ---- Clients
        'GetClients' => ['Clients', 'r', 'search, status (Active|Inactive|Closed), limitstart, limitnum (default 25), sorting (ASC|DESC), orderby (id|firstname|lastname|companyname|email|groupid|datecreated|status)'],
        'GetClientsDetails' => ['Clients', 'r', 'clientid or email, stats (bool: include invoice/service statistics)'],
        'GetClientGroups' => ['Clients', 'r', ''],
        'GetContacts' => ['Clients', 'r', 'userid, firstname, lastname, companyname, email, limitstart, limitnum'],
        'GetEmails' => ['Clients', 'r', 'clientid (required), date, subject, limitstart, limitnum'],
        'GetCancelledPackages' => ['Clients', 'r', 'limitstart, limitnum'],
        'GetUsers' => ['Clients', 'r', 'search, limitstart, limitnum, sorting'],
        'GetUserPermissions' => ['Clients', 'r', 'user_id, client_id'],
        'GetPermissionsList' => ['Clients', 'r', ''],
        'GetAffiliates' => ['Clients', 'r', 'userid, visitors, creditbalance, withdrawn, limitstart, limitnum'],
        'AddClient' => ['Clients', 'w', 'firstname, lastname, email, address1, city, state, postcode, country (ISO-2), phonenumber, password2, companyname, address2, currency (id), groupid, language, notes, tax_id, customfields (base64 serialized array), owner_user_id, skipvalidation (bool), noemail (bool)'],
        'UpdateClient' => ['Clients', 'w', 'clientid or clientemail, then any client field (firstname, lastname, companyname, email, address1, city, state, postcode, country, phonenumber, currency, groupid, notes, status Active|Inactive|Closed, credit, taxexempt, latefeeoveride, overideduenotices, separateinvoices, disableautocc, emailoptout, language, paymentmethod, customfields)'],
        'AddContact' => ['Clients', 'w', 'clientid, firstname, lastname, email, companyname, address1, city, state, postcode, country, phonenumber, generalemails, productemails, domainemails, invoiceemails, supportemails'],
        'UpdateContact' => ['Clients', 'w', 'contactid, any contact field'],
        'AddUser' => ['Clients', 'w', 'firstname, lastname, email, password2, language'],
        'UpdateUser' => ['Clients', 'w', 'user_id, firstname, lastname, email, language'],
        'UpdateUserPermissions' => ['Clients', 'w', 'user_id, client_id, permissions (comma list from GetPermissionsList)'],
        'CreateClientInvite' => ['Clients', 'w', 'client_id, email, permissions'],
        'ResetPassword' => ['Clients', 'w', 'id or email (sends the user a reset email)'],
        'AffiliateActivate' => ['Clients', 'w', 'userid'],
        'AddClientNote' => ['Clients', 'w', 'userid, notes, sticky (bool)'],
        'CloseClient' => ['Clients', 'f', 'clientid (closes the account and cancels its services)'],
        'DeleteClient' => ['Clients', 'f', 'clientid, deleteusers (bool), deletetransactions (bool)'],
        'DeleteContact' => ['Clients', 'f', 'contactid'],
        'DeleteUserClient' => ['Clients', 'f', 'user_id, client_id'],
        'GetClientPassword' => ['Clients', 'f', 'userid or email (legacy)'],

        // ---- Billing
        'GetInvoices' => ['Billing', 'r', 'userid, status (Paid|Unpaid|Cancelled|Refunded|Collections|Overdue|Draft|Payment Pending), limitstart, limitnum, orderby (id|invoicenumber|date|duedate|total|status), order (asc|desc)'],
        'GetInvoice' => ['Billing', 'r', 'invoiceid'],
        'GetTransactions' => ['Billing', 'r', 'invoiceid, clientid, transid'],
        'GetCredits' => ['Billing', 'r', 'clientid'],
        'GetPayMethods' => ['Billing', 'r', 'clientid, paymethodid, type (BankAccount|CreditCard)'],
        'GetQuotes' => ['Billing', 'r', 'quoteid, userid, subject, stage, datecreated, lastmodified, validuntil, limitstart, limitnum'],
        'GetPaymentMethods' => ['Billing', 'r', '(lists active payment gateways)'],
        'GetCurrencies' => ['Billing', 'r', ''],
        'CreateInvoice' => ['Billing', 'w', 'userid, status (Draft|Unpaid|Paid|...), draft (bool), sendinvoice (bool), paymentmethod, taxrate, date, duedate, notes, itemdescription1, itemamount1, itemtaxed1 (repeat 2,3,...), autoapplycredit (bool)'],
        'UpdateInvoice' => ['Billing', 'w', 'invoiceid, status, paymentmethod, taxrate, date, duedate, datepaid, notes, itemdescription[lineid], itemamount[lineid], itemtaxed[lineid], newitemdescription[], newitemamount[], newitemtaxed[], deletelineids[], publish, publishandsendemail'],
        'AddInvoicePayment' => ['Billing', 'w', 'invoiceid, transid, gateway, amount, fees, date (Y-m-d H:i:s), noemail (bool)'],
        'ApplyCredit' => ['Billing', 'w', 'invoiceid, amount, noemail (bool)'],
        'AddCredit' => ['Billing', 'w', 'clientid, description, amount, date, type (add|remove)'],
        'AddBillableItem' => ['Billing', 'w', 'clientid, description, amount, invoiceaction (noinvoice|nextcron|nextinvoice|duedate|recur), recur, recurcycle, recurfor, duedate, hours'],
        'AddTransaction' => ['Billing', 'w', 'paymentmethod, userid, invoiceid, transid, date, description, amountin, amountout, fees, rate, credit (bool)'],
        'UpdateTransaction' => ['Billing', 'w', 'transactionid, userid, currency, gateway, date, description, amountin, fees, amountout, rate, transid, invoiceid, refundid'],
        'CapturePayment' => ['Billing', 'w', 'invoiceid, cvv'],
        'GenInvoices' => ['Billing', 'w', 'clientid, serviceids, domainids, addonids, noemails (bool) - runs invoice generation now'],
        'AddPayMethod' => ['Billing', 'w', 'clientid, type (BankAccount|CreditCard|RemoteBankAccount|RemoteCreditCard), description, gateway_module_name, card_number, card_expiry, bank_name, bank_account_type, bank_code, bank_account, set_as_default'],
        'UpdatePayMethod' => ['Billing', 'w', 'clientid, paymethodid, card_number, card_expiry, bank_name, bank_code, bank_account, set_as_default'],
        'CreateQuote' => ['Billing', 'w', 'subject, stage (Draft|Delivered|On Hold|Accepted|Lost|Dead), validuntil, userid (or firstname/lastname/email/...), lineitems (base64 serialized array of desc/qty/up/discount/taxable), customernotes, adminnotes'],
        'UpdateQuote' => ['Billing', 'w', 'quoteid, subject, stage, validuntil, lineitems, customernotes, adminnotes'],
        'SendQuote' => ['Billing', 'w', 'quoteid'],
        'AcceptQuote' => ['Billing', 'w', 'quoteid (converts the quote to an invoice)'],
        'DeleteQuote' => ['Billing', 'f', 'quoteid'],
        'DeletePayMethod' => ['Billing', 'f', 'clientid, paymethodid'],

        // ---- Orders
        'GetOrders' => ['Orders', 'r', 'id, userid, requestor_id, status (Pending|Active|Fraud|Cancelled), limitstart, limitnum'],
        'GetOrderStatuses' => ['Orders', 'r', ''],
        'GetPromotions' => ['Orders', 'r', 'code'],
        'AddOrder' => ['Orders', 'w', 'clientid, paymentmethod, pid[] , qty[], billingcycle[] (monthly|quarterly|semiannually|annually|biennially|triennially|onetime|free), domain[], domaintype[] (register|transfer), regperiod[], eppcode[], configoptions[] (base64 serialized), customfields[], priceoverride[], addons[], hostname[], rootpw[], nameserver1..5, promocode, promooverride, affid, noinvoice, noinvoiceemail, noemail, contactid, clientip'],
        'AcceptOrder' => ['Orders', 'w', 'orderid, serverid, serviceusername, servicepassword, registrar, sendregistrar (bool), autosetup (bool), sendemail (bool)'],
        'PendingOrder' => ['Orders', 'w', 'orderid'],
        'CancelOrder' => ['Orders', 'w', 'orderid, cancelsub (bool), noemail (bool)'],
        'FraudOrder' => ['Orders', 'w', 'orderid, cancelsub (bool)'],
        'OrderFraudCheck' => ['Orders', 'w', 'orderid, ipaddress'],
        'DeleteOrder' => ['Orders', 'f', 'orderid'],

        // ---- Products
        'GetProducts' => ['Products', 'r', 'pid, gid, module'],
        'AddProduct' => ['Products', 'w', 'name, gid, type (hostingaccount|reselleraccount|server|other), description, shortdescription, tagline, hidden, paytype (free|onetime|recurring), pricing[currencyid][monthly|quarterly|semiannually|annually|biennially|triennially|msetupfee|...], module (e.g. cpanel, directadmin, plesk), servergroupid, configoption1..24 (module package settings, e.g. configoption1 = WHM package name), autosetup (""|on|payment|order), welcomeemail, stockcontrol, qty, tax, isFeatured, showdomainoptions, order'],

        // ---- Services
        'GetClientsProducts' => ['Services', 'r', 'clientid, serviceid, pid, domain, username2, limitstart, limitnum'],
        'GetClientsAddons' => ['Services', 'r', 'serviceid, clientid, addonid'],
        'GetModuleQueue' => ['Services', 'r', 'relatedId, serviceType, moduleName, moduleAction, since'],
        'UpdateClientProduct' => ['Services', 'w', 'serviceid, pid, serverid, regdate, nextduedate, terminationdate, domain, firstpaymentamount, recurringamount, paymentmethod, billingcycle, status (Pending|Active|Suspended|Terminated|Cancelled|Fraud|Completed), notes, serviceusername, servicepassword, overideautosuspend, overidesuspenduntil, dedicatedip, assignedips, diskusage, disklimit, bwusage, bwlimit, suspendreason, promoid, autorecalc, customfields, configoptions'],
        'UpdateClientAddon' => ['Services', 'w', 'id, status, terminationdate, addonid, name, setupfee, recurring, billingcycle, nextduedate, notes'],
        'UpgradeProduct' => ['Services', 'w', 'serviceid, type (product|configoptions), newproductid, newproductbillingcycle, configoptions, paymentmethod, promocode, calconly (bool)'],
        'AddCancelRequest' => ['Services', 'w', 'serviceid, type (Immediate|End of Billing Period), reason'],
        'ModuleCreate' => ['Services', 'w', 'serviceid (provisions the account on the server)'],
        'ModuleSuspend' => ['Services', 'w', 'serviceid, suspendreason'],
        'ModuleUnsuspend' => ['Services', 'w', 'serviceid'],
        'ModuleChangePackage' => ['Services', 'w', 'serviceid'],
        'ModuleChangePw' => ['Services', 'w', 'serviceid, servicepassword'],
        'ModuleCustom' => ['Services', 'w', 'serviceid, func_name'],
        'ModuleTerminate' => ['Services', 'f', 'serviceid (removes the account and its data from the server)'],

        // ---- Domains
        'GetClientsDomains' => ['Domains', 'r', 'clientid, domainid, domain, limitstart, limitnum'],
        'DomainWhois' => ['Domains', 'r', 'domain (availability check)'],
        'DomainGetNameservers' => ['Domains', 'r', 'domainid'],
        'DomainGetLockingStatus' => ['Domains', 'r', 'domainid'],
        'DomainGetWhoisInfo' => ['Domains', 'r', 'domainid'],
        'GetTLDPricing' => ['Domains', 'r', 'currencyid, clientid'],
        'GetRegistrars' => ['Domains', 'r', ''],
        'DomainRegister' => ['Domains', 'w', 'domainid or domain, idnlanguage'],
        'DomainRenew' => ['Domains', 'w', 'domainid or domain, regperiod'],
        'DomainTransfer' => ['Domains', 'w', 'domainid or domain, eppcode'],
        'DomainUpdateNameservers' => ['Domains', 'w', 'domainid or domain, ns1, ns2, ns3, ns4, ns5'],
        'DomainUpdateLockingStatus' => ['Domains', 'w', 'domainid, lockstatus (bool)'],
        'DomainUpdateWhoisInfo' => ['Domains', 'w', 'domainid, xml'],
        'DomainToggleIdProtect' => ['Domains', 'w', 'domainid, idprotect (bool)'],
        'DomainRequestEPP' => ['Domains', 'w', 'domainid'],
        'UpdateClientDomain' => ['Domains', 'w', 'domainid, type, regdate, nextduedate, expirydate, domain, firstpaymentamount, recurringamount, registrar, regperiod, paymentmethod, status, notes, dnsmanagement, emailforwarding, idprotection, donotrenew, autorecalc, updatens, ns1..ns5'],
        'CreateOrUpdateTLD' => ['Domains', 'w', 'extension, currency_code, register, renew, transfer (pricing arrays by years), id_protection, dns_management, email_forwarding, epp_required, auto_registrar, grace_period_days, grace_period_fee, redemption_period_days, redemption_period_fee'],
        'DomainRelease' => ['Domains', 'f', 'domainid, newtag'],

        // ---- Support
        'GetTickets' => ['Support', 'r', 'deptid, clientid, email, status (Open|Answered|Customer-Reply|Closed|"Awaiting Reply"|"All Active Tickets"), subject, ignore_dept_assignments, limitstart, limitnum'],
        'GetTicket' => ['Support', 'r', 'ticketid or ticketnum, repliessort (ASC|DESC)'],
        'GetTicketNotes' => ['Support', 'r', 'ticketid'],
        'GetTicketCounts' => ['Support', 'r', 'ignoreDepartmentAssignments, includeCountsByStatus'],
        'GetTicketAttachment' => ['Support', 'r', 'relatedid, type (ticket|reply|note), index'],
        'GetSupportDepartments' => ['Support', 'r', 'ignore_dept_assignments'],
        'GetSupportStatuses' => ['Support', 'r', 'deptid'],
        'GetTicketPredefinedCats' => ['Support', 'r', ''],
        'GetTicketPredefinedReplies' => ['Support', 'r', 'catid'],
        'GetAnnouncements' => ['Support', 'r', 'limitstart, limitnum'],
        'OpenTicket' => ['Support', 'w', 'deptid, subject, message, clientid (or name + email), contactid, priority (Low|Medium|High), serviceid, domainid, admin (bool: opened by admin), markdown (bool), customfields, attachments'],
        'AddTicketReply' => ['Support', 'w', 'ticketid, message, adminusername (reply as staff), clientid, contactid, name, email, status, markdown (bool), noemail (bool), attachments'],
        'AddTicketNote' => ['Support', 'w', 'ticketid or ticketnum, message, markdown (bool)'],
        'UpdateTicket' => ['Support', 'w', 'ticketid, deptid, status, subject, userid, name, email, cc, priority, flag (admin id), removeFlag, message, markdown'],
        'UpdateTicketReply' => ['Support', 'w', 'replyid, message, markdown'],
        'MergeTicket' => ['Support', 'w', 'ticketid, mergeticketids (comma list), newsubject'],
        'AddAnnouncement' => ['Support', 'w', 'date, title, announcement, published (bool)'],
        'UpdateAnnouncement' => ['Support', 'w', 'announcementid, date, title, announcement, published'],
        'DeleteTicket' => ['Support', 'f', 'ticketid'],
        'DeleteTicketReply' => ['Support', 'f', 'ticketid, replyid'],
        'DeleteTicketNote' => ['Support', 'f', 'noteid'],
        'DeleteAnnouncement' => ['Support', 'f', 'announcementid'],
        'BlockTicketSender' => ['Support', 'f', 'ticketid, delete (bool)'],

        // ---- Projects (Project Management addon)
        'GetProjects' => ['Projects', 'r', 'userid, title, status, adminid, created, duedate, completed, lastmodified, limitstart, limitnum'],
        'GetProject' => ['Projects', 'r', 'projectid'],
        'CreateProject' => ['Projects', 'w', 'title, adminid, userid, status, created, duedate, completed, ticketids, invoiceids'],
        'UpdateProject' => ['Projects', 'w', 'projectid, title, adminid, userid, status, duedate, completed, ticketids, invoiceids'],
        'AddProjectTask' => ['Projects', 'w', 'projectid, duedate, adminid, task, notes, completed, billed'],
        'UpdateProjectTask' => ['Projects', 'w', 'taskid, projectid, duedate, adminid, task, notes, completed'],
        'AddProjectMessage' => ['Projects', 'w', 'projectid, message, adminid'],
        'StartTaskTimer' => ['Projects', 'w', 'timerid, projectid, adminid, start_time, end_time'],
        'EndTaskTimer' => ['Projects', 'w', 'timerid, projectid, adminid, end_time'],
        'DeleteProjectTask' => ['Projects', 'f', 'projectid, taskid'],

        // ---- System
        'WhmcsDetails' => ['System', 'r', ''],
        'GetStats' => ['System', 'r', 'timeline_days'],
        'GetActivityLog' => ['System', 'r', 'userid, date, user, description, ipaddress, limitstart, limitnum'],
        'GetAdminDetails' => ['System', 'r', ''],
        'GetAdminUsers' => ['System', 'r', 'roleid, email, include_disabled'],
        'GetStaffOnline' => ['System', 'r', ''],
        'GetAutomationLog' => ['System', 'r', 'startdate, enddate, namespace'],
        'GetEmailTemplates' => ['System', 'r', 'type (general|product|domain|invoice|support|affiliate|admin), language'],
        'GetToDoItems' => ['System', 'r', 'status, limitstart, limitnum'],
        'GetToDoItemStatuses' => ['System', 'r', ''],
        'GetServers' => ['System', 'r', 'serviceId, addon, fetchStatus (bool)'],
        'GetHealthStatus' => ['System', 'r', 'fetchStatus (bool)'],
        'GetConfigurationValue' => ['System', 'r', 'setting'],
        'GetModuleConfigurationParameters' => ['System', 'r', 'moduleType (gateway|registrar|addon|fraud), moduleName'],
        'ListOAuthCredentials' => ['System', 'r', 'grantType, sortField, sortOrder, limit'],
        'EncryptPassword' => ['System', 'r', 'password2'],
        'SendEmail' => ['System', 'w', 'messagename (template name) or customtype (general|product|domain|invoice|support|affiliate) + customsubject + custommessage, id (related id), customvars (base64 serialized)'],
        'SendAdminEmail' => ['System', 'w', 'messagename or custommessage + customsubject, type (system|account|support), deptid, mergefields'],
        'LogActivity' => ['System', 'w', 'clientid, description'],
        'AddBannedIp' => ['System', 'w', 'ip, reason, days, expires'],
        'UpdateAdminNotes' => ['System', 'w', 'notes'],
        'UpdateToDoItem' => ['System', 'w', 'itemid, adminid, date, title, description, status, duedate'],
        'TriggerNotificationEvent' => ['System', 'w', 'notification_identifier, title, message, url, status, statusStyle, attributes'],
        'SetConfigurationValue' => ['System', 'f', 'setting, value'],
        'ActivateModule' => ['System', 'f', 'moduleType (gateway|registrar|addon|fraud), moduleName, parameters'],
        'DeactivateModule' => ['System', 'f', 'moduleType, moduleName, newGateway'],
        'UpdateModuleConfiguration' => ['System', 'f', 'moduleType, moduleName, parameters'],
        'DecryptPassword' => ['System', 'f', 'password2'],
        'CreateSsoToken' => ['System', 'f', 'client_id or user_id, destination (clientarea:services|clientarea:invoices|sso:custom_redirect|...), sso_redirect_path, service_id, domain_id - returns a one-time login link'],
        'CreateOAuthCredential' => ['System', 'f', 'grantType, scope, name, serviceId, description, logoUri, redirectUri'],
        'UpdateOAuthCredential' => ['System', 'f', 'credentialId, name, description, logoUri, redirectUri, scope'],
        'DeleteOAuthCredential' => ['System', 'f', 'credentialId'],
        'ValidateLogin' => ['System', 'f', 'email, password2'],
    ];

    /** Access level an API action needs. Unknown actions need Full access. */
    public static function access($action)
    {
        return isset(self::ACTIONS[$action]) ? self::ACTIONS[$action][1] : 'f';
    }

    /** Permission category of an API action. Unknown actions belong to System. */
    public static function category($action)
    {
        return isset(self::ACTIONS[$action]) ? self::ACTIONS[$action][0] : 'System';
    }

    public static function scopeAllows($scope, $access)
    {
        $have = isset(self::SCOPES[$scope]) ? self::SCOPES[$scope] : 0;
        $need = isset(self::LEVELS[$access]) ? self::LEVELS[$access] : 3;
        return $have >= $need;
    }

    /** Case-insensitive lookup so "getclients" resolves to "GetClients". */
    public static function canonical($action)
    {
        $action = trim((string) $action);
        if (isset(self::ACTIONS[$action])) {
            return $action;
        }
        foreach (self::ACTIONS as $name => $_) {
            if (strcasecmp($name, $action) === 0) {
                return $name;
            }
        }
        return $action;
    }

    public static function search($query, $category, $scope)
    {
        $query = strtolower(trim((string) $query));
        $out = [];
        foreach (self::ACTIONS as $name => $info) {
            if ($category !== '' && strcasecmp($category, $info[0]) !== 0) {
                continue;
            }
            if ($query !== '' && strpos(strtolower($name . ' ' . $info[2]), $query) === false) {
                continue;
            }
            $out[] = [
                'action' => $name,
                'category' => $info[0],
                'access' => ['r' => 'read', 'w' => 'write', 'f' => 'full'][$info[1]],
                'allowed_for_this_connector' => self::scopeAllows($scope, $info[1]),
                'parameters' => $info[2],
            ];
        }
        return $out;
    }
}
