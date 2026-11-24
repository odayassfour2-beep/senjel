<?php
/**
 * ===================================================================
 * نظام إدارة المدرسة المتكامل — ملف الإعدادات الأساسي (config.php)
 * ===================================================================
 * يُرجى تعديل المتغيرات أدناه بما يتناسب مع بيانات الاستضافة وقاعدة البيانات.
 */

// نوع محرك قاعدة البيانات: 'mysql' للاستضافة والإنتاج، أو 'sqlite' للتجربة المحلية السريعة
defined('DB_DRIVER')   || define('DB_DRIVER', 'mysql');

// إعدادات اتصال MySQL
defined('DB_HOST')     || define('DB_HOST', 'localhost');
defined('DB_PORT')     || define('DB_PORT', 3306);
defined('DB_NAME')     || define('DB_NAME', 'jemne');
defined('DB_USER')     || define('DB_USER', 'root');
defined('DB_PASS')     || define('DB_PASS', '1234567890o');

// بادئة أسماء الجداول
defined('DB_PREFIX')   || define('DB_PREFIX', 'sc_');

// مسار ملف SQLite في حال تم اختيار محرك sqlite
defined('DB_SQLITE_PATH') || define('DB_SQLITE_PATH', __DIR__ . '/data/school.sqlite');

// حساب الإدارة الأولي — يُنشأ تلقائياً عند أول تشغيل
defined('INITIAL_USER') || define('INITIAL_USER', 'admin');
defined('INITIAL_PASS') || define('INITIAL_PASS', 'admin123'); // كلمة مرور قوية (>= 6 أحرف)

// وضع الفحص وتشخيص الأخطاء (اجعله false في الإنتاج لحماية النظام)
defined('DEBUG_SETUP')  || define('DEBUG_SETUP', false);

// رابط الموقع الإلكتروني الأساسي
defined('SITE_URL')     || define('SITE_URL', 'http://localhost/jemne');

// مفتاح مهمة Cron التلقائية (اختياري للنسخ الاحتياطي عبر المهام المجدولة)
defined('CRON_KEY')     || define('CRON_KEY', 'Sch00l_Cr0n_S3cur3_K3y_2026');
