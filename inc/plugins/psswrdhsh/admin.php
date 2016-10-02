<?php
/**
 * Password Hash
 * Originally By Tom Moore (@mooseypx)
 * Extended by Josh Harmon
 */
// Disallow direct access to this file for security reasons
defined ('IN_MYBB') or die('Direct initialization of this file is not allowed.');

global $lang;
if (defined('IN_ADMINCP') && stripos($lang->language, 'admin') !== false) {
	global $lang;
	$lang->load('config_plugins_psswrdhsh');
}

/**
 * Global Functions
 */
function psswrdhsh_info()
{
	return [
		'name' => 'Better Password Practices (formerly Password Hash)',
		'description' => "Changes MyBB's default password hashing method and sets some built-in configuration options to make MyBB adhere to modern password-handling standards.",
		'website' => '',
		'author' => 'Tom Moore & Josh Harmon',
		'authorsite' => '',
		'version' => '1.1',
		'guid'  => '',
		'compatibility' => '18*'
	];
}

/**
 * Install / Uninstall Functions
 * When installed, this plugin doesn't automatically activate
 */
function psswrdhsh_is_installed()
{
	global $db, $settings;

	if (isset($settings['psswrd_cost'])) {
		return true;
	}

	if ($db->field_exists('passwordhash', 'users')) {
		return true;
	}

	return false;
}

function psswrdhsh_install()
{
	global $db, $lang;

	// Dependencies
	// PluginLibrary
	if (!file_exists(PLUGINLIBRARY)) {
		flash_message($lang->error_pwh_pl_missing, 'error');
		admin_redirect('index.php?module=config-plugins');
	}

	global $PL;
	$PL or require_once PLUGINLIBRARY;

	if ($PL->version < 12) {
	        flash_message($lang->error_pwh_pl_old, 'error');
	        admin_redirect('index.php?module=config-plugins');
	}

	// PHP
	if (version_compare(PHP_VERSION, '5.5.0', '<')) {
		flash_message($lang->sprintf($lang->error_pwh_php_old, PHP_VERSION), 'error');
		admin_redirect('index.php?module=config-plugins');
	}

	// MySQL?
	if ($db->type != 'mysql' && $db->type != 'mysqli') {
		flash_message($lang->error_pwh_db_type, 'error');
		admin_redirect('index.php?module=config-plugins');
	}

	// Uninstall
	psswrdhsh_uninstall();

	// Settings
	// Figure out the optimal cost for this server
	// From: http://php.net/manual/en/function.password-hash.php
	// Password used is 8 chars + 2 numbers
	$target = 0.05;
	$cost = 8;

	do {
		++$cost;
		$start = microtime(true);
		password_hash('z2d4BYAzsB', PASSWORD_BCRYPT, ['cost' => $cost]);
		$end = microtime(true);
	} while (($end - $start) < $target);

	$settings = [
		[
			'name' => 'psswrd_cost',
			'title' => 'Password Hashing Cost',
			'description' => 'The algorithmic cost that should be used when hashing passwords. <b>This has been automatically set for the server your forum is running on for optimal performance</b>.'.
/*Trailing concat .*/			 '<br />Only alter this if you know what it does. No, really. Leave this alone. If you make this too small, you diminish the benefits of using bcrypt instead of MD5. If you make this too high, you open up the possibility for an easy (D)DoS attack against your forum.',
			'optionscode' => 'numeric',
			'value' => (int)$cost,
			'disporder' => 7, // Should appear after the max password length
			'gid' => 9, // member
			'isdefault' => 0
		]
	];

	$db->insert_query_multiple('settings', $settings);
	rebuild_settings();

	// DB changes
	$db->add_column('users', 'passwordhash', "VARCHAR(72) NOT NULL DEFAULT '' AFTER username");
}

function psswrdhsh_uninstall()
{
	global $db;

	// Settings
	$db->delete_query('settings', "name = 'psswrd_cost'");
	rebuild_settings();

	// DB Changes
	if ($db->field_exists('passwordhash', 'users')) {
		$db->drop_column('users', 'passwordhash');
	}
}

/**
 * Activate / Deactivate functions
 * These should mostly just modify core files
 */
function psswrdhsh_activate()
{
	global $lang, $mybb;

	if (psswrdhsh_core_edits('activate') === false) {
		psswrdhsh_uninstall();

		flash_message($lang->error_pwh_activate, 'error');
		admin_redirect('index.php?module=config-plugins');
	}
	
	// assume core edits succeeded
	
	if ($mybb->settings['regtype'] == "randompass") {
		
		// Sending the user a random password, which thus becomes _their_ password
		// for at least some amount of time, in plain text across media that may or
		// may not be secure and/or confidential is just an absolutely braindamaged
		// idea that should never, ever be used on a modern site. </endrant>

		$decent_regtype_optionscode = "select
instant=Instant Activation
verify=Send Email Verification
admin=Administrator Activation
both=Email Verification & Administrator Activation";
		
		
		$db->update_query("settings", ["value" => "verify"], "name = 'regtype'");
		$db->update_query("settings", ["optionscode" => $decent_regtype_optionscode], "name = 'regtype'");
		rebuild_settings();
	}
	
	if (!$mybb->settings["requirecomplexpasswords"]) {
		$db->update_query("settings", ["value" => 1], "name = 'requirecomplexpasswords'");
		rebuild_settings();
	}
	
	// Since we're requiring complex passwords, the min length should already be
	// considered 8 in the core, so that part is alright. But let's remove the unnecessary
	// ceiling to the password length, since bcrypt will work with the first 72
	// characters of input and 72 bytes really isn't all that much data to send.
	
	if ($mybb->settings["maxpasswordlength"] < 72) {
		$db->update_query("settings", ["value" => 72], "name = 'maxpasswordlength'");
		rebuild_settings();
	}
	
	// redirect back informing the admin of any settings we changed
	flash_message($lang->pwh_activate_regtype_changed, 'error');
	admin_redirect('index.php?module=config-plugins');
}

function psswrdhsh_deactivate()
{
	global $lang, $mybb;
	$PL or require_once PLUGINLIBRARY;

	if (psswrdhsh_core_edits('deactivate') === false) {
		flash_message($lang->error_pwh_deactivate, 'error');
		admin_redirect('index.php?module=config-plugins');
	}
	
	// Give the admin the stupid send-random-password regtype back, although part of me
	// feels like I really shouldn't do that for the safety of anybody whose passwords
	// get transmitted in such a careless way
	$bad_regtypes_optioncode = "select
instant=Instant Activation
verify=Send Email Verification
randompass=Send Random Password
admin=Administrator Activation
both=Email Verification & Administrator Activation";

	$db->update_query("settings", ["optionscode" => $bad_regtypes_optionscode], "name = 'regtype'");
	rebuild_settings();
}

/**
 * Supporting Functions
 */
function psswrdhsh_core_edits($action)
{
	global $mybb, $PL;
	$PL or require_once PLUGINLIBRARY;

	$results = [];
	if ($action == 'activate') {
		$results[] = $PL->edit_core('psswrdhsh', 'inc/functions_user.php', [
			[
				'search' => 'function validate_password_from_uid',
				'replace' => 'function old_validate_password_from_uid($uid, $password, $user = array())',
				'before' => 'require_once MYBB_ROOT.\'inc/plugins/psswrdhsh/functions_user.php\';'
			]
		], true) ?: 0;
		
		// disable option for sending the user a random password upon registration in plain text... it's just stupid
		$results[] = $PL->edit_core('psswrdhsh', 'admin/inc/class_form.php', [
			[
				'search' => '$select_add = \'\';',
				'after' => '\t\t\t$select_add .= ($value == "randompass") ? "disabled" : ""'
			]
		], true) ?: 0;
	} else if ($action == 'deactivate') {
		$results[] = $PL->edit_core('psswrdhsh', 'inc/functions_user.php', [], true) ?: 0;
		$results[] = $PL->edit_core('psswrdhsh', 'admin/inc/class_form.php', [], true) ?: 0;
	}

	// Return false if we have failed to apply edits
	if (in_array(0, $results)) {
		return false;
	} else {
		return true;
	}
}
