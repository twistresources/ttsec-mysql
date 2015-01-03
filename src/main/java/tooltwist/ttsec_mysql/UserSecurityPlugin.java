package tooltwist.ttsec_mysql;

import com.dinaa.data.XData;
import com.dinaa.data.XNodes;
import com.dinaa.xpc.*;
import com.dinaa.xpc.backend.XpcSecurityImpl;

import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tooltwist.basic.AuthConfigSingleton;
import tooltwist.misc.MiscInternal;
import tooltwist.misc.TtConfig;

/**
 * Insert the type's description here.
 * Creation date: (13/03/2001 9:50:58 AM)
 * @author: Administrator    
 */
public class UserSecurityPlugin extends XpcSecurityImpl // implements XpcSecurityPluggin, XpcSecurityAccessController
{
	static Logger logger = LoggerFactory.getLogger(UserSecurityPlugin.class);
	public static final String USERTYPE_CUSTOMER = "C"; // coCustomerMaster
	public static final String USERTYPE_EMPLOYEE = "E"; // coEmployee
	public static final String USERTYPE_SUPPLIER = "S"; // coSupplierMaster
	public static final String USERTYPE_CONTACT = "T"; //coContactMaster
	public static final String USERTYPE_ORGANIZATION = "O"; //rmOrganization 

	public static final String DEFAULT_APPEARANCE = "silver";

	/*
	 * Note from Phil:
	 * The same error message must be displayed for invalid username and
	 * invalid password. If they have different error messages, it allows
	 * confirmation that a user id exists and assists hacking attempts.
	 */
	static final String INVALID_USERNAME_OR_PASSWORD = "Invalid User Id or Password";
	static final String INVALID_USERNAME_FOR_SSO = "Invalid User Id. Application is SSO enabled and your user id is not registred with PHINZA. Please contact your PHINZA administrator.";
	
	/**
	 * Roles for the current user
	 */
	private boolean rolesAreLoaded = false;

	/**
	 * TestSecurityPluggin constructor comment.
	 * @throws XpcException 
	 */
	public UserSecurityPlugin() throws XpcException
	{
		super();
	}

	@Override
	public boolean login(
		String userType,
		String userName,
		String password,
		XpcSecurityPlugginParameter details)
		throws XpcSecurityException, XpcException
	{
		String appearance = DEFAULT_APPEARANCE;
		AuthConfigSingleton authconf = AuthConfigSingleton.getInstance();

		// Perhaps create a temporary login
		if (userName.equalsIgnoreCase("temporaryCustomerLogin")) // BRAXTONHACK
		{
			this.setValue("temporaryLogin", "yes");
			// set details for this customer
			this.setValue("userName", "Temporary Login");
			this.setValue("fullName", "Temporary User");
			this.setValue("userType", TtConfig.USER_TYPE);
			this.setValue("companyNo", "");
			this.setValue("buildingNo", "");
			this.setValue("coCustomerMasterLink", "");
			this.setValue("customerName", "Temporary Login");
			this.setValue("userMenu", "temporaryMenu");
			this.setUserPreference("language", "EN");
			this.setUserPreference("lineSpeed", "L");

			// Set the appearance
			setAppearance(this, appearance);
			return true;
		}

		//	boolean useTransactionIsolation = false;
		com.dinaa.sql.DatabaseContext context = null;
		java.sql.Connection con = null;
		try
		{
			// Work out the SQL
			String sql =
				"select password, fullname, user_type, user_link, language, administrator, appearance, line_speed, initial_menu_option, initial_menu from sys_user_master where user_code='"
					+ userName
					+ "'"
					+ " and fsa_pseudo_delete = 'N'";
			context = MiscInternal.getContextFromSecurity(this);
			con = context.getConnection();
			Statement s = con.createStatement();
			logger.debug("sql=" + sql);
			java.sql.ResultSet rs = s.executeQuery(sql);

			// Create an XML document from the result
			if (!rs.next())
			{
				// Unknown user
				//throw new XpcException(this.getClass().getName() + ": Unknown user: " + userName);
				if (authconf.isLocalAuthenticationFlag() == true)
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, INVALID_USERNAME_OR_PASSWORD);
				else
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, INVALID_USERNAME_FOR_SSO);
				return (false);
			}
			int col = 1;
			String db_password = rs.getString(col++);
			String db_fullname = rs.getString(col++);
			String db_user_type = rs.getString(col++);
			String db_user_link = rs.getString(col++);
			String db_language = rs.getString(col++);
			String db_administrator = rs.getString(col++);
			appearance = rs.getString(col++);
			String db_lineSpeed = rs.getString(col++);
			String db_initialMenuOption = rs.getString(col++);
			String db_initialMenu = rs.getString(col++);
			rs.close();
			s.close();

			// Check the password, etc
			if (db_fullname == null || db_fullname.equals(""))
				db_fullname = userName;
			if (db_language == null || db_language.equals(""))
				db_language = "EN";
			if (appearance == null || appearance.equals(""))
				appearance = DEFAULT_APPEARANCE;
			if (db_lineSpeed == null || db_lineSpeed.equals(""))
				db_lineSpeed = "L"; // default to LAN
			if (db_initialMenuOption == null)
				db_initialMenuOption = "";
			if (db_initialMenu == null)
				db_initialMenu = "Config";

			// Do password checking only if Local Authentication is required.
			if (authconf.isLocalAuthenticationFlag() == true)
			{
				if (authconf.isEncryptPasswordsFlag() == true)
				{
					tooltwist.misc.StringEncrypter se = new tooltwist.misc.StringEncrypter();
					String dbTextPassword = se.decrypt(db_password);
					if (!password.equals(dbTextPassword))
					{
						details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, INVALID_USERNAME_OR_PASSWORD);
						return (false);
					}					
				}
				else
				{
					if (!password.equals(db_password))
					{
						details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, INVALID_USERNAME_OR_PASSWORD);
						return (false);
					}
				}
			}

			// Set the admin flag.
			this.setValue("isAdministrator", nvl(db_administrator, "N"));

			// Get User Menu
			logger.debug("UserMenu is [" + db_initialMenu + "]");
			this.setValue("userMenu", nvl(db_initialMenu));

			String companyNo;

			// Get extra details from the related table, depending upon user type	
			if (db_user_type.equals(USERTYPE_CUSTOMER))
			{
				// Customer
				sql =
					"select customer_no, customer_name, company_no, building_no from co_customer_master where co_customer_master_link = '"
						+ db_user_link
						+ "'";
				s = con.createStatement();
				logger.debug("sql=" + sql);
				rs = s.executeQuery(sql);
				if (!rs.next())
				{
					//throw new XpcException(this.getClass().getName() + ": Missing co_customer_master record for user '" + userName + "'");
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined customer record for user '" + userName + "'");
					return false;
				}
				col = 1;
				String db_customer_no = rs.getString(col++);
				String db_customer_name = rs.getString(col++);
				String db_company_no = rs.getString(col++);
				String db_building_no = rs.getString(col++);
				rs.close();
				s.close();

				// set details for this customer
				this.setValue("userName", nvl(userName));
				this.setValue("fullName", nvl(db_fullname));
				this.setValue("userType", nvl(db_user_type));
				this.setValue("companyNo", nvl(db_company_no));
				this.setValue("buildingNo", nvl(db_building_no));
				this.setValue("coCustomerMasterLink", nvl(db_user_link));
				this.setValue("customerNo", nvl(db_customer_no));
				this.setValue("customerName", nvl(db_customer_name));
				this.setValue("initialMenuOption", db_initialMenuOption);

				this.setUserPreference("language", db_language);
				this.setUserPreference("lineSpeed", db_lineSpeed);
				companyNo = db_company_no;
			}
			else if (db_user_type.equals(USERTYPE_EMPLOYEE))
			{
				// Employee
				sql =
					"select employee_id, display_name, company_no from co_employee where co_employee_link = '"
						+ db_user_link
						+ "'";
				;
				s = con.createStatement();
				logger.debug("sql=" + sql);
				rs = s.executeQuery(sql);
				if (!rs.next())
				{
					//throw new XpcException(this.getClass().getName() + ": Missing co_employee record for user '" + userName + "'");
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined employee record for user '" + userName + "'");
					return false;
				}
				col = 1;
				String db_employee_id = rs.getString(col++);
				String db_employee_name = rs.getString(col++);
				String db_company_no = rs.getString(col++);
				//String db_building_no = rs.getString(col++);
				rs.close();
				s.close();

				// set details for this employee
				this.setValue("userName", nvl(userName));
				this.setValue("fullName", nvl(db_fullname));
				this.setValue("userType", nvl(db_user_type));
				this.setValue("companyNo", nvl(db_company_no));
				//sec.setValue("buildingNo", nvl(db_building_no));
				this.setValue("coEmployeeLink", nvl(db_user_link));
				this.setValue("employeeId", nvl(db_employee_id));
				this.setValue("employeeName", nvl(db_employee_name));
				this.setValue("initialMenuOption", db_initialMenuOption);

				this.setUserPreference("language", db_language);
				this.setUserPreference("lineSpeed", db_lineSpeed);
				companyNo = db_company_no;
			}
			else if (db_user_type.equals(USERTYPE_SUPPLIER))
			{
				// Supplier
				sql =
					"select supplier_name, company_no, building_no from co_supplier_master where supplier_no = '"
						+ db_user_link
						+ "'";
				;
				s = con.createStatement();
				logger.debug("sql=" + sql);
				rs = s.executeQuery(sql);
				if (!rs.next())
				{
					//throw new XpcException(this.getClass().getName() + ": Missing co_supplier_master record for user '" + userName + "'");
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined supplier record for user '" + userName + "'");
					return false;
				}
				col = 1;
				String db_supplier_name = rs.getString(col++);
				String db_company_no = rs.getString(col++);
				String db_building_no = rs.getString(col++);
				rs.close();
				s.close();

				// set details for this supplier
				this.setValue("userName", nvl(userName));
				this.setValue("fullName", nvl(db_fullname));
				this.setValue("userType", nvl(db_user_type));
				this.setValue("companyNo", nvl(db_company_no));
				this.setValue("buildingNo", nvl(db_building_no));
				this.setValue("supplierNo", nvl(db_user_link));
				this.setValue("supplierName", nvl(db_supplier_name));
				this.setValue("initialMenuOption", db_initialMenuOption);

				this.setUserPreference("language", "en");
				this.setUserPreference("lineSpeed", db_lineSpeed);
				companyNo = db_company_no;
			}
			else if (db_user_type.equals(USERTYPE_CONTACT))
			{
				// Contact
				sql =
					"select contact_id, display_name, company_no from co_contact_master where co_contact_master_link = '"
						+ db_user_link
						+ "'";
				;
				s = con.createStatement();
				logger.debug("sql=" + sql);
				rs = s.executeQuery(sql);
				if (!rs.next())
				{
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined contact record for user '" + userName + "'");
					return false;
				}
				col = 1;
				String db_contact_id = rs.getString(col++);
				String db_display_name = rs.getString(col++);
				String db_company_no = rs.getString(col++);
				rs.close();
				s.close();

				//set details for this contact
				this.setValue("userName", nvl(userName));
				this.setValue("fullName", nvl(db_fullname));
				this.setValue("userType", nvl(db_user_type));
				this.setValue("companyNo", nvl(db_company_no));
				this.setValue("coContactMasterLink", nvl(db_user_link));
				this.setValue("contactId", nvl(db_contact_id));
				this.setValue("displayName", nvl(db_display_name));
				this.setValue("initialMenuOption", db_initialMenuOption);

				this.setUserPreference("language", "en");
				this.setUserPreference("lineSpeed", db_lineSpeed);
				companyNo = db_company_no;
			}
			else if (db_user_type.equals(USERTYPE_ORGANIZATION))
			{
				// Organization
				sql =
					"select org_id, org_name, company_no from rm_organisation where rm_organisation_link= '"
						+ db_user_link
						+ "'";
				;
				s = con.createStatement();
				logger.debug("sql=" + sql);
				rs = s.executeQuery(sql);
				if (!rs.next())
				{
					details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined organization record for user '" + userName + "'");
					return false;
				}
				col = 1;
				String db_org_id = rs.getString(col++);
				String db_org_name = rs.getString(col++);
				String db_company_no = rs.getString(col++);
				rs.close();
				s.close();

				// set details for this organization
				this.setValue("userName", nvl(userName));
				this.setValue("fullName", nvl(db_fullname));
				this.setValue("userType", nvl(db_user_type));
				this.setValue("companyNo", nvl(db_company_no));
				this.setValue("rmOrganisationLink", nvl(db_user_link));
				this.setValue("orgId", nvl(db_org_id));
				this.setValue("orgName", nvl(db_org_name));
				this.setValue("initialMenuOption", db_initialMenuOption);

				this.setUserPreference("language", "en");
				this.setUserPreference("lineSpeed", db_lineSpeed);
				companyNo = db_company_no;
			}
			else
			{
				//throw new SecurityException("Incorrect user type in sys_user_master ("+db_user_type+")");
				details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Unknown user type");
				return false;
			}

			sql = "select name, name_alt_lang from co_company where company_no = " + companyNo;
			s = con.createStatement();
			logger.debug("sql=" + sql);
			rs = s.executeQuery(sql);
			if (!rs.next())
			{
				//throw new XpcException(this.getClass().getName() + ": Missing co_supplier_master record for user '" + userName + "'");
				details.setValue(XpcSecurity.VARIABLE_ERROR_MESSAGE, "Undefined company no '" + companyNo + "'");
				return false;
			}
			String db_company_name = rs.getString("name");
			String db_company_name_alt_lang = rs.getString("name_alt_lang");
			rs.close();
			s.close();

			// set details for this supplier
			this.setValue("companyName", nvl(db_company_name));
			this.setValue("companyNameAltLang", nvl(db_company_name_alt_lang));
		}
		catch (java.sql.SQLException e)
		{
			logger.error("SQLException " + e);
			throw new XpcException(this.getClass().getName() + ": Could not validate login: " + e);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			logger.error("Error loading security details from database", e);
		}
		finally
		{
			if (con != null)
				context.releaseConnection(con);
		}

		// Set the appearance
		setAppearance(this, appearance);

		// Login is okay
		return true;
	}

	// STD-1  The sec parameter should be removed
	public static void setAppearance(XpcSecurity sec, String appearance) throws XpcException
	{
		com.dinaa.sql.DatabaseContext context = null;
		java.sql.Connection con = null;
		try
		{
			// Get details of the required appearance
			String sql =
				"select basic_screen_set, extra_screen_set, stylesheet_path, image_path, image_format from sys_appearance where appearance='"
					+ appearance
					+ "'";
			context = MiscInternal.getContextFromSecurity(sec);
			con = context.getConnection();
			Statement s = con.createStatement();
			logger.debug("sql=" + sql);
			ResultSet rs = s.executeQuery(sql);

			// Set security values and preferences from the result
			String basicScreenSet;
			String extraScreenSet;
			String stylesheetPath;
			String imagePath;
			String imageFormat;
			if (rs.next())
			{
				int col = 1;
				basicScreenSet = rs.getString(col++);
				extraScreenSet = rs.getString(col++);
				stylesheetPath = rs.getString(col++);
				imagePath = rs.getString(col++);
				imageFormat = rs.getString(col++);
			}
			else
			{
				// Default (should not happen)
				basicScreenSet = "b";
				extraScreenSet = "gator";
				stylesheetPath = "/ttsvr/stylesheet/gator";
				imagePath = "/ttsvr/images/b/gator";
				imageFormat = ".png";
			}
			rs.close();
			s.close();

			// Set the preference and values
			sec.setValue("appearance", nvl(appearance));
			sec.setValue("stylesheetPath", nvl(stylesheetPath));
			sec.setValue("imagePath", nvl(imagePath));
			sec.setValue("imageFormat", nvl(imageFormat));
			sec.setUserPreference("look", nvl(basicScreenSet));
			sec.setUserPreference("look2", nvl(extraScreenSet));
		}
		catch (java.sql.SQLException e)
		{
			//catLog.error("SQLException " + e);
			throw new XpcException(UserSecurityPlugin.class.getName() + ": Could not validate login: " + e);
		}
		finally
		{
			if (con != null)
				context.releaseConnection(con);
		}
	}

	/**
	 * See if a user may perform the specified operation to a Dinaa entity.
	 *
	 * @return boolean
	 * @param domain Domain of the Dinaa entity.
	 * @param entityName The name of the entity.
	 * @param operation The required operation.
	 */
	@Override
	public boolean mayAccessEntity(String entityName, String operation)
	{
		return true; //ZZZZ
	}
	
	/**
	 * See if a user identified may run a specific Dinaa module.
	 *
	 * @return boolean
	 * @param domain Domain of the module.
	 * @param name The name of the module.
	 */
	@Override
	public boolean mayAccessModule(String name) 
	{
		return true; //ZZZZ
	}

	/**
	 * Check that the roles for this user have been loaded
	 * @return
	 */
	private void checkRolesLoaded()
	{
		if (rolesAreLoaded)
			return;

		synchronized (this) {
			if (rolesAreLoaded)
				return;
			
		logger.debug(">> loadRoles");
		
		String userName = (String) this.getValue("userName");

		
		ArrayList<String> userRoleMenuItemList = new ArrayList<String>();
		ArrayList<String> userPrivilegeList = new ArrayList<String>();
		
		ArrayList<String> userRoleList = new ArrayList<String>();

		try
		{
			
			// If Administrator do not attempt to load any roles. Futile
			// excerise.
			String isAdministrator = (String) this.getValue("isAdministrator");
			if (isAdministrator.equals("Y"))
			{
				this.setValue(XpcSecurity.VARIABLE_USERS_ROLE_LIST, loadAllRolesForAdmin(this));
				return;
			}

			Xpc xpc = new Xpc(this);
			xpc.start("phinza.D.sysUserRoles", "select");
			xpc.attrib("userCode", userName);
			XData output = xpc.run();
			
			logger.debug("UserRoles DATA: " + output.getXml());
			// Not necessary for each user to have a role, group role to
			// suffice.
			// ... for later.
			if ("select".equals(output.getRootType()))
			{
				// Comes here if the user has roles assigned to them. Ignores
				// group roles.
				// Now get all the roles that the user has access to.
				XNodes userRoleRecords = output.getNodes("/*/sysUserRoles");
				for (userRoleRecords.first(); userRoleRecords.next();)
				{
					userRoleList.add(userRoleRecords.getText("roleCode"));
					
					xpc = new Xpc(this);
					xpc.start("phinza.D.sysRoleMenus", "select");
					xpc.attrib("roleCode", userRoleRecords.getText("roleCode"));
					XData outputMenuItems = xpc.run();
					
					if ("select".equals(outputMenuItems.getRootType()))
					{
						XNodes roleItemRecords = outputMenuItems.getNodes("/*/sysRoleMenus");
						for (roleItemRecords.first(); roleItemRecords.next();)
						{
							String menuItem = roleItemRecords.getText("menuItem");
							userRoleMenuItemList.add(menuItem);
						}
					}
					
					xpc = new Xpc(this);
					xpc.start("phinza.D.sysRolePrivileges", "select");
					xpc.attrib("roleCode", userRoleRecords.getText("roleCode"));
					XData outputPrivileges = xpc.run();

					if ("select".equals(outputPrivileges.getRootType()))
					{
						XNodes privRecords = outputPrivileges.getNodes("/*/sysRolePrivileges");
						for (privRecords.first(); privRecords.next();)
						{
							String privilegeName = privRecords.getText("privilegeName");
							userPrivilegeList.add(privilegeName);
						}
					}
				}
			}
			
			// Now try for group roles.
			xpc = new Xpc(this);
			xpc.start("phinza.D.sysGroupMap", "select");
			xpc.attrib("userCode", userName);
			XData groupOutput = xpc.run();
			
			if ("notfound".equals(groupOutput.getRootType()))
			{
				
				// No User roles, now no groups found for this user. Thus
				// this user does not have any roles at all.
				logger.warn("User " + userName + " does not have roles and does not belong to any group.");

			}
			else
			{
				// Groups found for this user. Now see if we can find Group
				// roles for each Group.
				XNodes groupMapRecords = groupOutput.getNodes("/*/sysGroupMap");
				for (groupMapRecords.first(); groupMapRecords.next();)
				{
					
					xpc = new Xpc(this);
					xpc.start("phinza.D.sysGroupRoles", "select");
					xpc.attrib("groupCode", groupMapRecords.getText("groupCode"));
					XData grpRoleOutput = xpc.run();
					
					if ("select".equals(grpRoleOutput.getRootType()))
					{
						// Group Roles found. Go on and add the items to the
						// Array.
						XNodes groupRoleRecords = grpRoleOutput.getNodes("/*/sysGroupRoles");
						for (groupRoleRecords.first(); groupRoleRecords.next();)
						{
							userRoleList.add(groupRoleRecords.getText("roleCode"));
							
							xpc = new Xpc(this);
							xpc.start("phinza.D.sysRoleMenus", "select");
							xpc.attrib("roleCode", groupRoleRecords.getText("roleCode"));
							XData outputMenuItems = xpc.run();

							if ("select".equals(outputMenuItems.getRootType()))
							{
								XNodes roleItemRecords = outputMenuItems.getNodes("/*/sysRoleMenus");
								for (roleItemRecords.first(); roleItemRecords.next();)
								{
									String menuItem = roleItemRecords.getText("menuItem");
									userRoleMenuItemList.add(menuItem);
								}
							}
							
							xpc = new Xpc(this);
							xpc.start("phinza.D.sysRolePrivileges", "select");
							xpc.attrib("roleCode", groupRoleRecords.getText("roleCode"));
							XData outputPrivileges = xpc.run();

							if ("select".equals(outputPrivileges.getRootType()))
							{
								XNodes privRecords = outputPrivileges.getNodes("/*/sysRolePrivileges");
								for (privRecords.first(); privRecords.next();)
								{
									String privilegeName = privRecords.getText("privilegeName");
									userPrivilegeList.add(privilegeName);
								}
							}
						}
					}
				}
			}
			
			// STD-1  These should probably be local variables (But see if these variables are used elsewhere first)
			this.setValue(XpcSecurity.VARIABLE_USERS_MENU_ITEMS_LIST, userRoleMenuItemList);
			this.setValue(XpcSecurity.VARIABLE_USERS_PRIVILEGES_LIST, userPrivilegeList);
			this.setValue(XpcSecurity.VARIABLE_USERS_ROLE_LIST, userRoleList);

		}
		catch (Exception e)
		{
			logger.warn("Exception occured loading roles: " + e);
			return;
		}
		} // synchronized
		
	}
	
	/**
	 * Load all roles for the current company
	 * @param req
	 * 		The Request object
	 * @param res
	 * 		The response object
	 * @return
	 * 		list of all roles
	 * @throws ServletException
	 */
	private static ArrayList<String> loadAllRolesForAdmin(XpcSecurity sec)
	{
		// Stored in XpcSecurity all applicable User Roles for the currently logged user (roles will be use in Service Catalog Security)
		// This method will load all roles since currently logged user is an admin
		String companyNo = sec.getString("companyNo");
		
		try
		{
			
			ArrayList<String> userRoleList = new ArrayList<String>();
			Xpc xpc = new Xpc(sec);
			xpc.start("phinza.D.sysRoles", "select");
			xpc.attrib("companyNo", companyNo);
			XData output = xpc.run();
			
			if (output.getRootType().equals("select")) {
				XNodes userRoleRecords = output.getNodes("/*/sysRoles");
				for (userRoleRecords.first(); userRoleRecords.next();)
				{
					String roleCode = userRoleRecords.getText("roleCode");
					userRoleList.add(roleCode);	
				}
			}
			else
			{
				logger.warn("User Admin for Company No." + companyNo + " does not have roles.");
			}
			return userRoleList;
		}
		catch (Exception e)
		{
			logger.warn("Exception occured loading roles: " + e);
			return null;
		}
	}
	

	@Override
	public boolean hasRole(String role) {
		
		String isAdministrator = getString("isAdministrator");
		if (isAdministrator.equals("Y"))
			return true;

		// See if the user has this roles specified
		checkRolesLoaded();
		Object obj = this.getValue(XpcSecurity.VARIABLE_USERS_ROLE_LIST);
		if (obj instanceof List<?>) {
			List<?> roleList = (List<?>) obj;
			return roleList.contains(role);
		}
		return false; // Should not happen.
	}


	/**
	 * Substitutes empty string ("") for null values 
	 * @param source
	 * @return String 
	 */
	private static String nvl(String source)
	{
		if (source == null)
			return "";

		return source;
	}

	/**
	 * Substitutes replaceStr for null values of source
	 * @param source
	 * @param replaceStr
	 * @return String
	 */
	private static String nvl(String source, String replaceStr)
	{
		if (source == null)
			return "";

		return source;
	}

}
