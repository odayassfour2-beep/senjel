<?php
/**
 * ===================================================================
 * نظام إدارة المدرسة المتكامل — الواجهة الخلفية (api.php)
 * ===================================================================
 * واجهة برمجية كاملة تدعم:
 * - MySQL و SQLite عبر PDO و Prepared Statements
 * - القفل التفاؤلي (Optimistic Locking) للبيانات الموحدة في sc_store
 * - نظام صلاحيات مشدد للمدير، المعلمين، الطلاب، وأولياء الأمور
 * - تنقية وتجريد البيانات في بوابتي الطالب وولي الأمر ومنع تسريب البيانات الحساسة
 * - حماية مشددة من القوة الغاشمة (Brute Force) وقفل IP والحسابات
 * - تشفير الجلسات بشفرة sha256 لكافة التوكنات
 * - نظام النسخ الاحتياطي التلقائي والمضغوط بـ gzdeflate وبداية العام الدراسي
 * ===================================================================
 */

// إيقاف إظهار الأخطاء للمستخدمين لمنع تسريب مسارات الخادم
ini_set('display_errors', '0');
error_reporting(E_ALL);

// معالج استثناءات عام يُرجع JSON مهذباً برمز 500
set_exception_handler(function ($e) {
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
    }
    // تسجيل الخطأ داخلياً دون كشف تفاصيله للواجهة
    error_log("SchoolApp Exception: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    
    $resp = [
        'ok' => false,
        'error' => 'server_error',
        'message' => 'حدث خطأ غير متوقع في الخادم. يرجى المحاولة لاحقاً.'
    ];
    if (defined('DEBUG_SETUP') && DEBUG_SETUP) {
        $resp['debug'] = $e->getMessage();
    }
    echo json_encode($resp, JSON_UNESCAPED_UNICODE);
    exit;
});

// ترويسات الاستجابة
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');

// تضمين ملف الإعدادات
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    echo json_encode([
        'ok' => false,
        'error' => 'config_missing',
        'message' => 'ملف الإعدادات config.php غير موجود. يرجى التأكد من رفعه بشكل صحيح.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
require_once $configFile;

// دالة الاتصال بقاعدة البيانات مع دعم الإنشاء التلقائي
function getDbConnection() {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $driver = defined('DB_DRIVER') ? strtolower(DB_DRIVER) : 'mysql';
    $prefix = defined('DB_PREFIX') ? DB_PREFIX : 'sc_';

    if ($driver === 'sqlite') {
        $sqlitePath = defined('DB_SQLITE_PATH') ? DB_SQLITE_PATH : __DIR__ . '/data/school.sqlite';
        $sqliteDir = dirname($sqlitePath);
        if (!is_dir($sqliteDir)) {
            @mkdir($sqliteDir, 0755, true);
        }
        $pdo = new PDO("sqlite:" . $sqlitePath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
        $pdo->exec("PRAGMA journal_mode = WAL;");
    } else {
        $host = defined('DB_HOST') ? DB_HOST : 'localhost';
        $port = defined('DB_PORT') ? DB_PORT : 3306;
        $dbName = defined('DB_NAME') ? DB_NAME : 'school';
        $user = defined('DB_USER') ? DB_USER : 'root';
        $pass = defined('DB_PASS') ? DB_PASS : '';

        try {
            $dsn = "mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4";
            $pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ]);
        } catch (PDOException $e) {
            // محاولة إنشاء قاعدة البيانات إذا لم تكن موجودة
            if ($e->getCode() == 1049) {
                try {
                    $tmpPdo = new PDO("mysql:host={$host};port={$port};charset=utf8mb4", $user, $pass);
                    $tmpPdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    $pdo = new PDO("mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4", $user, $pass, [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                    ]);
                } catch (Exception $e2) {
                    throw $e;
                }
            } else {
                throw $e;
            }
        }
    }

    ensureTablesExist($pdo, $driver, $prefix);
    return $pdo;
}

// إنشاء الجداول تلقائياً عند أول تشغيل
function ensureTablesExist($pdo, $driver, $prefix) {
    if ($driver === 'sqlite') {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `{$prefix}store` (
                id INTEGER PRIMARY KEY,
                data TEXT NOT NULL,
                ver INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}public` (
                id TEXT PRIMARY KEY,
                val TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}auth` (
                id INTEGER PRIMARY KEY DEFAULT 1,
                username TEXT NOT NULL,
                pass_hash TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                email TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}users` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pass_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'teacher',
                permissions TEXT,
                subjects TEXT,
                classes TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}tokens` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                uid INTEGER NOT NULL,
                sid TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}stu` (
                id TEXT PRIMARY KEY,
                pass_hash TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 1,
                must_change_pass INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}parents` (
                phone_key TEXT PRIMARY KEY,
                pass_hash TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 1,
                must_change_pass INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}tries` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}resets` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}pm` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_uid INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                receiver_uid INTEGER NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}presence` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                uid INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                role TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}audit` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS `{$prefix}snaps` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snap_hash TEXT NOT NULL,
                data_gz BLOB NOT NULL,
                ver INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT 'النظام'
            );
        ");
    } else {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS `{$prefix}store` (
              `id` INT NOT NULL DEFAULT 1,
              `data` LONGTEXT NOT NULL,
              `ver` INT NOT NULL DEFAULT 1,
              `updated_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}public` (
              `id` VARCHAR(64) NOT NULL,
              `val` LONGTEXT NOT NULL,
              `updated_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}auth` (
              `id` INT NOT NULL DEFAULT 1,
              `username` VARCHAR(64) NOT NULL,
              `pass_hash` VARCHAR(255) NOT NULL,
              `is_default` INT NOT NULL DEFAULT 0,
              `email` VARCHAR(128) NOT NULL DEFAULT '',
              `updated_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}users` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `username` VARCHAR(64) NOT NULL,
              `pass_hash` VARCHAR(255) NOT NULL,
              `full_name` VARCHAR(128) NOT NULL,
              `role` VARCHAR(32) NOT NULL DEFAULT 'teacher',
              `permissions` LONGTEXT,
              `subjects` LONGTEXT,
              `classes` LONGTEXT,
              `active` INT NOT NULL DEFAULT 1,
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              UNIQUE KEY `idx_sc_users_username` (`username`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}tokens` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `token_hash` VARCHAR(64) NOT NULL,
              `expires_at` DATETIME NOT NULL,
              `uid` INT NOT NULL,
              `sid` VARCHAR(64) NOT NULL DEFAULT '',
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              UNIQUE KEY `idx_sc_tokens_hash` (`token_hash`),
              KEY `idx_sc_tokens_uid` (`uid`),
              KEY `idx_sc_tokens_expires` (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}stu` (
              `id` VARCHAR(64) NOT NULL,
              `pass_hash` VARCHAR(255) NOT NULL,
              `is_default` INT NOT NULL DEFAULT 1,
              `must_change_pass` INT NOT NULL DEFAULT 1,
              `updated_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}parents` (
              `phone_key` VARCHAR(16) NOT NULL,
              `pass_hash` VARCHAR(255) NOT NULL,
              `is_default` INT NOT NULL DEFAULT 1,
              `must_change_pass` INT NOT NULL DEFAULT 1,
              `updated_at` DATETIME NOT NULL,
              PRIMARY KEY (`phone_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}tries` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `ip` VARCHAR(45) NOT NULL,
              `username` VARCHAR(64) NOT NULL,
              `attempted_at` DATETIME NOT NULL,
              `success` INT NOT NULL DEFAULT 0,
              PRIMARY KEY (`id`),
              KEY `idx_sc_tries_ip` (`ip`, `attempted_at`),
              KEY `idx_sc_tries_user` (`username`, `attempted_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}resets` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `token_hash` VARCHAR(64) NOT NULL,
              `expires_at` DATETIME NOT NULL,
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              UNIQUE KEY `idx_sc_resets_hash` (`token_hash`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}pm` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `sender_uid` INT NOT NULL,
              `sender_name` VARCHAR(128) NOT NULL,
              `receiver_uid` INT NOT NULL,
              `subject` VARCHAR(255) NOT NULL,
              `body` LONGTEXT NOT NULL,
              `is_read` INT NOT NULL DEFAULT 0,
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_sc_pm_receiver` (`receiver_uid`, `is_read`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}presence` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `session_id` VARCHAR(64) NOT NULL,
              `uid` INT NOT NULL,
              `user_name` VARCHAR(128) NOT NULL,
              `role` VARCHAR(32) NOT NULL,
              `last_seen` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              UNIQUE KEY `idx_sc_presence_session` (`session_id`),
              KEY `idx_sc_presence_last` (`last_seen`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}audit` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `uid` INT NOT NULL,
              `user_name` VARCHAR(128) NOT NULL,
              `action` VARCHAR(64) NOT NULL,
              `details` LONGTEXT,
              `ip` VARCHAR(45) NOT NULL DEFAULT '',
              `created_at` DATETIME NOT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_sc_audit_action` (`action`),
              KEY `idx_sc_audit_created` (`created_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            CREATE TABLE IF NOT EXISTS `{$prefix}snaps` (
              `id` INT AUTO_INCREMENT NOT NULL,
              `snap_hash` VARCHAR(64) NOT NULL,
              `data_gz` LONGBLOB NOT NULL,
              `ver` INT NOT NULL,
              `created_at` DATETIME NOT NULL,
              `created_by` VARCHAR(128) NOT NULL DEFAULT 'النظام',
              PRIMARY KEY (`id`),
              KEY `idx_sc_snaps_hash` (`snap_hash`),
              KEY `idx_sc_snaps_created` (`created_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ");
    }

    // تهيئة حساب المدير الأولي إذا لم يكن موجوداً
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM `{$prefix}auth` WHERE id = 1");
    $stmt->execute();
    if ($stmt->fetchColumn() == 0) {
        $initUser = defined('INITIAL_USER') ? INITIAL_USER : 'admin';
        $initPass = defined('INITIAL_PASS') ? INITIAL_PASS : 'admin123';
        $isDefault = (strlen($initPass) < 6 || $initPass === '1234' || $initPass === 'admin') ? 1 : 0;
        $hash = password_hash($initPass, PASSWORD_DEFAULT);
        $now = date('Y-m-d H:i:s');
        
        $ins = $pdo->prepare("INSERT INTO `{$prefix}auth` (id, username, pass_hash, is_default, email, updated_at) VALUES (1, :u, :p, :d, '', :t)");
        $ins->execute([':u' => $initUser, ':p' => $hash, ':d' => $isDefault, ':t' => $now]);
    }

    // تهيئة الصفحة العامة المبدئية في sc_public
    $stmtPub = $pdo->prepare("SELECT COUNT(*) FROM `{$prefix}public` WHERE id = 'home'");
    $stmtPub->execute();
    if ($stmtPub->fetchColumn() == 0) {
        $defaultHome = [
            'school_name' => 'مدارس جيميناي النموذجية الأهلية',
            'slogan' => 'صرح تربوي متميز لرعاية الإبداع وبناء قادة المستقبل',
            'academic_year' => '2026/2027',
            'directorate' => 'الإدارة العامة للتربية والتعليم',
            'about' => 'تأسست مدارسنا لتكون نموذجاً رائداً في التعليم والتربية الحديثة، حيث نحرص على توفير بيئة تعليمية ذكية ومتطورة تُنمي مواهب الطلاب الأكاديمية والمهارية وتغرس فيهم القيم الإنسانية النبيلة.',
            'features' => [
                ['title' => 'كادر تعليمي نخبوي', 'desc' => 'نخبة من خيرة المعلمين والمعلمات ذوي الكفاءة العالية والشغف التربوي.'],
                ['title' => 'مناهج وبيئة رقمية ذكية', 'desc' => 'مختبرات ذكية، شاشات تفاعلية، ومنظومة متابعة إلكترونية فورية للدرجات والحضور.'],
                ['title' => 'رعاية ومتابعة شاملة', 'desc' => 'تواصل دوري مع أولياء الأمور وتقارير متابعة أسبوعية تعزز الشراكة التربوية.'],
                ['title' => 'أنشطة لا منهجية متقدمة', 'desc' => 'أندية للذكاء الاصطناعي، الروبوت، الفنون، الرياضة، والخطابة.'],
            ],
            'announcements' => [
                ['id' => '1', 'title' => 'بدء التسجيل للعام الدراسي الجديد 2026/2027', 'date' => date('Y-m-d'), 'content' => 'يسر إدارة المدرسة الإعلان عن فتح باب القبول والتسجيل للعام الدراسي الجديد لكافة المراحل.'],
                ['id' => '2', 'title' => 'انطلاق الأنشطة الثقافية والرياضية المدرسية', 'date' => date('Y-m-d'), 'content' => 'ندعو جميع الطلاب للمشاركة في مسابقات الإبداع الثقافي والبطولة الرياضية المدرسية.']
            ],
            'contact' => [
                'phone' => '+970 599 000 000',
                'phone2' => '+972 544 000 000',
                'email' => 'info@school.edu',
                'address' => 'شارع النهضة التعليمي — مبنى المدارس الرئيسي',
                'map_embed' => ''
            ],
            'hero_buttons' => ['student' => true, 'staff' => true, 'news' => true],
            'stats' => ['students' => '650+', 'classes' => '10', 'sections' => '24', 'subjects' => '14'],
            'sections_visible' => ['hero' => true, 'stats' => true, 'about' => true, 'features' => true, 'news' => true, 'contact' => true],
            'colors' => [
                'primary' => '#1e3a8a',
                'accent' => '#f59e0b',
                'bg_dark' => '#0f172a'
            ]
        ];
        $ins = $pdo->prepare("INSERT INTO `{$prefix}public` (id, val, updated_at) VALUES ('home', :v, :t)");
        $ins->execute([':v' => json_encode($defaultHome, JSON_UNESCAPED_UNICODE), ':t' => date('Y-m-d H:i:s')]);
    }

    // تهيئة البيانات الموحدة sc_store
    $stmtStore = $pdo->prepare("SELECT COUNT(*) FROM `{$prefix}store` WHERE id = 1");
    $stmtStore->execute();
    if ($stmtStore->fetchColumn() == 0) {
        $defaultStore = createInitialStoreData();
        $ins = $pdo->prepare("INSERT INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, 1, :t)");
        $ins->execute([':d' => json_encode($defaultStore, JSON_UNESCAPED_UNICODE), ':t' => date('Y-m-d H:i:s')]);
    }
}

// إنشاء هيكل البيانات الأولي الشامل للمدرسة
function createInitialStoreData() {
    return [
        'meta' => [
            'school_name' => 'مدارس جيميناي النموذجية الأهلية',
            'academic_year' => '2026/2027',
            'directorate' => 'الإدارة العامة للتربية والتعليم',
            'phone' => '0599000000',
            'logo_url' => '',
            'stamp_url' => '',
            'signature_url' => '',
            'parent_portal_enabled' => true,
            'student_portal_enabled' => true,
            'student_portal_perms' => [
                'grades' => true,
                'attendance' => true,
                'violations' => true,
                'notes' => true,
                'homework' => true,
                'schedule' => true
            ],
            'backup_interval' => 'daily', // 12h, daily, 2days, weekly, off
            'backup_keep_count' => 10,
            'auto_logout_minutes' => 60,
            'last_backup_at' => null,
            'last_data_hash' => ''
        ],
        'classes' => [
            ['id' => 'c1', 'name' => 'الصف الأول الأساسي', 'level' => 1, 'eval_system' => 'rating_only'],
            ['id' => 'c2', 'name' => 'الصف الثاني الأساسي', 'level' => 2, 'eval_system' => 'rating_only'],
            ['id' => 'c3', 'name' => 'الصف الثالث الأساسي', 'level' => 3, 'eval_system' => 'rating_only'],
            ['id' => 'c4', 'name' => 'الصف الرابع الأساسي', 'level' => 4, 'eval_system' => 'rating_only'],
            ['id' => 'c5', 'name' => 'الصف الخامس الأساسي', 'level' => 5, 'eval_system' => 'numeric'],
            ['id' => 'c6', 'name' => 'الصف السادس الأساسي', 'level' => 6, 'eval_system' => 'numeric'],
            ['id' => 'c7', 'name' => 'الصف السابع الأساسي', 'level' => 7, 'eval_system' => 'both'],
            ['id' => 'c8', 'name' => 'الصف الثامن الأساسي', 'level' => 8, 'eval_system' => 'both'],
            ['id' => 'c9', 'name' => 'الصف التاسع الأساسي', 'level' => 9, 'eval_system' => 'both'],
            ['id' => 'c10', 'name' => 'الصف العاشر الأساسي', 'level' => 10, 'eval_system' => 'both']
        ],
        'sections' => [
            ['id' => 's1_1', 'class_id' => 'c1', 'name' => 'أ', 'homeroom_teacher' => 'أحمد محمود'],
            ['id' => 's1_2', 'class_id' => 'c1', 'name' => 'ب', 'homeroom_teacher' => 'سارة علي'],
            ['id' => 's2_1', 'class_id' => 'c2', 'name' => 'أ', 'homeroom_teacher' => 'خالد إبراهيم'],
            ['id' => 's3_1', 'class_id' => 'c3', 'name' => 'أ', 'homeroom_teacher' => 'فاطمة عمر'],
            ['id' => 's4_1', 'class_id' => 'c4', 'name' => 'أ', 'homeroom_teacher' => 'محمود ياسين'],
            ['id' => 's5_1', 'class_id' => 'c5', 'name' => 'أ', 'homeroom_teacher' => 'عمر عبد الله'],
            ['id' => 's6_1', 'class_id' => 'c6', 'name' => 'أ', 'homeroom_teacher' => 'يوسف حسن'],
            ['id' => 's7_1', 'class_id' => 'c7', 'name' => 'أ', 'homeroom_teacher' => 'بلال كريم'],
            ['id' => 's8_1', 'class_id' => 'c8', 'name' => 'أ', 'homeroom_teacher' => 'محمد سعيد'],
            ['id' => 's9_1', 'class_id' => 'c9', 'name' => 'أ', 'homeroom_teacher' => 'رامي خالد'],
            ['id' => 's10_1', 'class_id' => 'c10', 'name' => 'أ', 'homeroom_teacher' => 'حسام الدين']
        ],
        'subjects' => [
            ['id' => 'sub_isl', 'name' => 'التربية الإسلامية', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_ar', 'name' => 'اللغة العربية', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_en', 'name' => 'اللغة الإنجليزية', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_math', 'name' => 'الرياضيات', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_sci', 'name' => 'العلوم العامة', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_soc', 'name' => 'الدراسات الاجتماعية', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_it', 'name' => 'التكنولوجيا والبرمجة', 'max_score' => 100, 'exclude_gpa' => false],
            ['id' => 'sub_art', 'name' => 'التربية الفنية', 'max_score' => 100, 'exclude_gpa' => true],
            ['id' => 'sub_sport', 'name' => 'التربية الرياضية', 'max_score' => 100, 'exclude_gpa' => true]
        ],
        'class_subjects' => [
            // افتراضياً كل الصفوف تدرس المواد الأساسية
        ],
        'grading_scales' => [
            ['id' => 'g1', 'name' => 'ممتاز', 'min_score' => 90, 'color' => '#10b981', 'active' => true],
            ['id' => 'g2', 'name' => 'جيد جداً', 'min_score' => 80, 'color' => '#3b82f6', 'active' => true],
            ['id' => 'g3', 'name' => 'جيد', 'min_score' => 70, 'color' => '#f59e0b', 'active' => true],
            ['id' => 'g4', 'name' => 'متوسط', 'min_score' => 60, 'color' => '#8b5cf6', 'active' => true],
            ['id' => 'g5', 'name' => 'مقبول', 'min_score' => 50, 'color' => '#ec4899', 'active' => true],
            ['id' => 'g6', 'name' => 'ضعيف', 'min_score' => 0, 'color' => '#ef4444', 'active' => true]
        ],
        'grade_components' => [
            ['id' => 'exams', 'name' => 'الاختبارات الشهرية', 'max_score' => 40],
            ['id' => 'participation', 'name' => 'المشاركة الصفية', 'max_score' => 10],
            ['id' => 'homework', 'name' => 'الواجبات والمهام', 'max_score' => 10],
            ['id' => 'final', 'name' => 'الاختبار النهائي', 'max_score' => 40]
        ],
        'cert_config' => [
            'template' => 'royal', // classic, modern, royal, formal, minimal, ornate
            'paper_size' => 'A4', // A4, A5
            'orientation' => 'portrait', // portrait, landscape
            'primary_color' => '#1e3a8a',
            'secondary_color' => '#d97706',
            'font_family' => 'Cairo',
            'title' => 'شهادة دراسية وتقويم فصلي',
            'calc_mode' => 'average', // average, weighted, single
            'term1_weight' => 50,
            'term2_weight' => 50,
            'pass_mark' => 50,
            'max_incomplete' => 2,
            'show_absence' => true,
            'show_rank' => true,
            'note_text' => 'نتمنى لطالبنا العزيز دوام التوفيق والنجاح الباهر.',
            'header_right' => "دولة فلسطين\nوزارة التربية والتعليم\nمديرية التربية والتعليم",
            'header_left' => "العام الدراسي: 2026/2027\nالفصل الدراسي الثاني\nشهادة تفوق"
        ],
        'students' => [
            [
                'id' => '1001',
                'national_id' => '401234567',
                'name' => 'محمد رامي عبد الله الأحمد',
                'birthdate' => '2015-04-12',
                'gender' => 'ذكر',
                'class_id' => 'c5',
                'section_id' => 's5_1',
                'parent_name' => 'رامي عبد الله الأحمد',
                'parent_national_id' => '901234567',
                'mother_name' => 'مريم يوسف',
                'parent_phone' => '0599123456',
                'phone2' => '0569123456',
                'phone3' => '',
                'address' => 'رام الله — الماصيون'
            ],
            [
                'id' => '1002',
                'national_id' => '402345678',
                'name' => 'فاطمة خالد سليم النجار',
                'birthdate' => '2015-08-20',
                'gender' => 'أنثى',
                'class_id' => 'c5',
                'section_id' => 's5_1',
                'parent_name' => 'خالد سليم النجار',
                'parent_national_id' => '902345678',
                'mother_name' => 'زينب عمر',
                'parent_phone' => '0598765432',
                'phone2' => '',
                'phone3' => '',
                'address' => 'رام الله — الطيرة'
            ],
            [
                'id' => '1003',
                'national_id' => '403456789',
                'name' => 'عمر طارق ياسين قاسم',
                'birthdate' => '2019-02-14',
                'gender' => 'ذكر',
                'class_id' => 'c1',
                'section_id' => 's1_1',
                'parent_name' => 'طارق ياسين قاسم',
                'parent_national_id' => '903456789',
                'mother_name' => 'سعاد محمود',
                'parent_phone' => '0599554433',
                'phone2' => '',
                'phone3' => '',
                'address' => 'رام الله — عين مصباح'
            ],
            [
                'id' => '1004',
                'national_id' => '404567890',
                'name' => 'سارة رامي عبد الله الأحمد',
                'birthdate' => '2018-11-05',
                'gender' => 'أنثى',
                'class_id' => 'c2',
                'section_id' => 's2_1',
                'parent_name' => 'رامي عبد الله الأحمد',
                'parent_national_id' => '901234567',
                'mother_name' => 'مريم يوسف',
                'parent_phone' => '0599123456', // نفس هاتف ولي أمر الطالب الأول لاختبار حساب ولي الأمر المتعدد
                'phone2' => '',
                'phone3' => '',
                'address' => 'رام الله — الماصيون'
            ]
        ],
        'attendance' => [
            ['student_id' => '1001', 'section_id' => 's5_1', 'date' => date('Y-m-d'), 'status' => 'present', 'note' => ''],
            ['student_id' => '1002', 'section_id' => 's5_1', 'date' => date('Y-m-d'), 'status' => 'present', 'note' => '']
        ],
        'violations' => [
            [
                'id' => 'v1',
                'student_id' => '1001',
                'type' => 'تأخر متكرر عن الطابور الصباحي',
                'degree' => 'الأولى',
                'action_taken' => 'تنبيه شفهي وتدوين في السجل',
                'date' => date('Y-m-d'),
                'recorded_by' => 'المرشد التربوي'
            ]
        ],
        'notes' => [
            [
                'id' => 'n1',
                'student_id' => '1001',
                'type' => 'positive', // positive, negative, general, academic, social, health
                'title' => 'مشاركة متميزة في الإذاعة المدرسية',
                'content' => 'أظهر الطالب فصاحة وإلقاء مميزاً في فقرة الإذاعة.',
                'date' => date('Y-m-d'),
                'author' => 'معلم اللغة العربية'
            ],
            [
                'id' => 'n2',
                'student_id' => '1001',
                'type' => 'health', // ملاحظة سرية لا تظهر للطالب ولا ولي الأمر
                'title' => 'حساسية من بعض الأطعمة',
                'content' => 'الطالب يعاني من حساسية خفيفة تجاه الفول السوداني، تم إبلاغ الممرض.',
                'date' => date('Y-m-d'),
                'author' => 'الصحة المدرسية'
            ]
        ],
        'grades' => [
            // درجات تجريبية للطالب 1001
            ['student_id' => '1001', 'term' => 1, 'subject_id' => 'sub_isl', 'exams' => 38, 'participation' => 10, 'homework' => 10, 'final' => 37, 'total' => 95, 'rating' => 'ممتاز'],
            ['student_id' => '1001', 'term' => 1, 'subject_id' => 'sub_ar', 'exams' => 36, 'participation' => 9, 'homework' => 10, 'final' => 36, 'total' => 91, 'rating' => 'ممتاز'],
            ['student_id' => '1001', 'term' => 1, 'subject_id' => 'sub_en', 'exams' => 35, 'participation' => 9, 'homework' => 9, 'final' => 35, 'total' => 88, 'rating' => 'جيد جداً'],
            ['student_id' => '1001', 'term' => 1, 'subject_id' => 'sub_math', 'exams' => 39, 'participation' => 10, 'homework' => 10, 'final' => 38, 'total' => 97, 'rating' => 'ممتاز'],
            ['student_id' => '1001', 'term' => 1, 'subject_id' => 'sub_sci', 'exams' => 37, 'participation' => 10, 'homework' => 10, 'final' => 36, 'total' => 93, 'rating' => 'ممتاز'],
            // درجات الصفوف الأولية (تقدير فقط) للطالب 1003
            ['student_id' => '1003', 'term' => 1, 'subject_id' => 'sub_isl', 'exams' => 0, 'participation' => 0, 'homework' => 0, 'final' => 0, 'total' => 0, 'rating' => 'ممتاز'],
            ['student_id' => '1003', 'term' => 1, 'subject_id' => 'sub_ar', 'exams' => 0, 'participation' => 0, 'homework' => 0, 'final' => 0, 'total' => 0, 'rating' => 'ممتاز'],
            ['student_id' => '1003', 'term' => 1, 'subject_id' => 'sub_math', 'exams' => 0, 'participation' => 0, 'homework' => 0, 'final' => 0, 'total' => 0, 'rating' => 'جيد جداً']
        ],
        'homework' => [
            [
                'id' => 'hw1',
                'class_id' => 'c5',
                'section_id' => 's5_1',
                'subject_id' => 'sub_math',
                'title' => 'حل تمارين صفحة 45 في كتاب الرياضيات',
                'desc' => 'يرجى حل الأسئلة من 1 إلى 5 في دفتر الواجبات وتسليمها غداً صباحاً.',
                'due_date' => date('Y-m-d', strtotime('+2 days')),
                'created_at' => date('Y-m-d H:i:s'),
                'teacher_name' => 'أ. حسام'
            ]
        ],
        'schedule' => [
            // جدول الحصص الأسبوعي للشعبة s5_1
            's5_1' => [
                'الأحد' => ['الرياضيات', 'اللغة العربية', 'العلوم العامة', 'التربية الإسلامية', 'اللغة الإنجليزية', 'التربية الرياضية', 'التكنولوجيا'],
                'الإثنين' => ['اللغة العربية', 'الرياضيات', 'الدراسات الاجتماعية', 'العلوم العامة', 'اللغة الإنجليزية', 'التربية الفنية', 'نشاط حر'],
                'الثلاثاء' => ['التربية الإسلامية', 'اللغة العربية', 'الرياضيات', 'اللغة الإنجليزية', 'العلوم العامة', 'الدراسات الاجتماعية', 'مكتبة'],
                'الأربعاء' => ['الرياضيات', 'اللغة العربية', 'العلوم العامة', 'التربية الإسلامية', 'اللغة الإنجليزية', 'تكنولوجيا', 'حاسوب'],
                'الخميس' => ['الدراسات الاجتماعية', 'اللغة العربية', 'الرياضيات', 'التربية الرياضية', 'العلوم العامة', 'إذاعة ونشاط', 'مراجعة']
            ]
        ],
        'plans' => [
            [
                'id' => 'p1',
                'subject_id' => 'sub_math',
                'class_id' => 'c5',
                'term' => 1,
                'title' => 'الخطة الفصلية لمادة الرياضيات - الفصل الأول',
                'goals' => 'إتقان العمليات الحسابية والكسور العشرية والنسبة المئوية والهندسة المستوية.',
                'progress' => 85,
                'updated_at' => date('Y-m-d')
            ]
        ],
        'message_templates' => [
            'absence' => "السلام عليكم ولي أمر الطالب {الاسم}، نفيدكم بغياب نجلكم عن الدوام المدرسي اليوم {التاريخ}. يرجى تزويدنا بالعذر أو التواصل مع المدرسة.",
            'grades' => "السلام عليكم ولي أمر الطالب {الاسم}، تم رصد نتائج الفصل الدراسي ونيل معدل {المعدل} والتقدير {التقدير}. نبارك لكم تفوقه.",
            'violation' => "السلام عليكم ولي أمر الطالب {الاسم}، نرجو التكرم بمراجعة إدارة المدرسة بخصوص الطالب {الاسم} للأهمية.",
            'parent_account' => "أهلاً بكم في بوابة أولياء الأمور لـ {اسم_المدرسة}. رابط الدخول: {رابط_الموقع} | رقم الهاتف: {الهاتف} | كلمة المرور المؤقتة: {كلمة_المرور}."
        ]
    ];
}

// دالة مساعدة لتطبيع أرقام الهواتف (آخر 9 أرقام لتسهيل مطابقة أرقام فلسطين وإسرائيل والمفتاح الدولي)
function normalizePhoneKey($phone) {
    $digits = preg_replace('/[^0-9]/', '', (string)$phone);
    if (strlen($digits) > 9) {
        return substr($digits, -9);
    }
    return $digits;
}

// دالة تسجيل التدقيق الأمني (Audit Log)
function logAudit($pdo, $prefix, $uid, $userName, $action, $details) {
    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $now = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("INSERT INTO `{$prefix}audit` (uid, user_name, action, details, ip, created_at) VALUES (:u, :n, :a, :d, :ip, :t)");
        $stmt->execute([
            ':u' => $uid,
            ':n' => $userName,
            ':a' => $action,
            ':d' => is_string($details) ? $details : json_encode($details, JSON_UNESCAPED_UNICODE),
            ':ip' => $ip,
            ':t' => $now
        ]);
    } catch (Exception $e) {}
}

// فحص الحماية من القوة الغاشمة (Brute Force)
function checkBruteForce($pdo, $prefix, $ip, $username) {
    $fifteenMinsAgo = date('Y-m-d H:i:s', time() - 900);
    $tenMinsAgo = date('Y-m-d H:i:s', time() - 600);

    // 1. فحص الـ IP: هل تجاوز 8 محاولات فاشلة خلال 15 دقيقة؟
    $stmtIp = $pdo->prepare("SELECT COUNT(*) FROM `{$prefix}tries` WHERE ip = :ip AND attempted_at >= :t AND success = 0");
    $stmtIp->execute([':ip' => $ip, ':t' => $fifteenMinsAgo]);
    if ($stmtIp->fetchColumn() >= 8) {
        return [
            'blocked' => true,
            'message' => 'تم حظر هذا الجهاز مؤقتاً لكثرة محاولات الدخول الفاشلة. يرجى الانتظار 15 دقيقة ثم إعادة المحاولة.'
        ];
    }

    // 2. فحص الحساب نفسه: هل تجاوز 10 محاولات فاشلة خلال 10 دقائق؟
    $stmtUser = $pdo->prepare("SELECT COUNT(*) FROM `{$prefix}tries` WHERE username = :u AND attempted_at >= :t AND success = 0");
    $stmtUser->execute([':u' => $username, ':t' => $tenMinsAgo]);
    if ($stmtUser->fetchColumn() >= 10) {
        return [
            'blocked' => true,
            'message' => 'تم قفل هذا الحساب مؤقتاً لمدة 10 دقائق لكثرة المحاولات الخاطئة. يرجى المحاولة لاحقاً أو استعادة كلمة المرور.'
        ];
    }

    return ['blocked' => false];
}

// تسجيل محاولة الدخول
function recordLoginAttempt($pdo, $prefix, $ip, $username, $success) {
    try {
        $now = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("INSERT INTO `{$prefix}tries` (ip, username, attempted_at, success) VALUES (:ip, :u, :t, :s)");
        $stmt->execute([':ip' => $ip, ':u' => $username, ':t' => $now, ':s' => $success ? 1 : 0]);
        // تنظيف المحاولات القديمة (> 24 ساعة) دورياً
        if (mt_rand(1, 20) === 1) {
            $yesterday = date('Y-m-d H:i:s', time() - 86400);
            $pdo->prepare("DELETE FROM `{$prefix}tries` WHERE attempted_at < :t")->execute([':t' => $yesterday]);
        }
    } catch (Exception $e) {}
}

// فحص الجلسة عبر التوكن في ترويسة X-Token
function authenticate($pdo, $prefix) {
    $token = $_SERVER['HTTP_X_TOKEN'] ?? $_REQUEST['token'] ?? '';
    if (empty($token)) {
        return null;
    }

    $tokenHash = hash('sha256', $token);
    $now = date('Y-m-d H:i:s');

    $stmt = $pdo->prepare("SELECT * FROM `{$prefix}tokens` WHERE token_hash = :h AND expires_at > :now LIMIT 1");
    $stmt->execute([':h' => $tokenHash, ':now' => $now]);
    $session = $stmt->fetch();
    if (!$session) {
        return null;
    }

    $uid = (int)$session['uid'];
    $sid = $session['sid'];

    if ($uid === 0) {
        // المدير العام
        $stmtAdmin = $pdo->prepare("SELECT id, username, is_default, email FROM `{$prefix}auth` WHERE id = 1 LIMIT 1");
        $stmtAdmin->execute();
        $admin = $stmtAdmin->fetch();
        return [
            'uid' => 0,
            'role' => 'admin',
            'username' => $admin['username'],
            'full_name' => 'المدير العام',
            'is_default' => (bool)$admin['is_default'],
            'email' => $admin['email'],
            'permissions' => ['all' => true],
            'sid' => '',
            'session_id' => $session['id']
        ];
    } elseif ($uid > 0) {
        // معلم أو موظف إداري
        $stmtUser = $pdo->prepare("SELECT id, username, full_name, role, permissions, subjects, classes, active FROM `{$prefix}users` WHERE id = :id LIMIT 1");
        $stmtUser->execute([':id' => $uid]);
        $user = $stmtUser->fetch();
        if (!$user || !$user['active']) return null;

        return [
            'uid' => (int)$user['id'],
            'role' => $user['role'],
            'username' => $user['username'],
            'full_name' => $user['full_name'],
            'permissions' => json_decode($user['permissions'] ?: '{}', true),
            'subjects' => json_decode($user['subjects'] ?: '[]', true),
            'classes' => json_decode($user['classes'] ?: '[]', true),
            'sid' => '',
            'session_id' => $session['id']
        ];
    } elseif ($uid === -2) {
        // طالب
        $stmtStu = $pdo->prepare("SELECT id, is_default, must_change_pass FROM `{$prefix}stu` WHERE id = :id LIMIT 1");
        $stmtStu->execute([':id' => $sid]);
        $stu = $stmtStu->fetch();
        return [
            'uid' => -2,
            'role' => 'student',
            'student_id' => $sid,
            'sid' => $sid,
            'must_change_pass' => $stu ? (bool)$stu['must_change_pass'] : false,
            'session_id' => $session['id']
        ];
    } elseif ($uid === -3) {
        // ولي أمر
        $stmtParent = $pdo->prepare("SELECT phone_key, is_default, must_change_pass FROM `{$prefix}parents` WHERE phone_key = :pk LIMIT 1");
        $stmtParent->execute([':pk' => $sid]);
        $par = $stmtParent->fetch();
        return [
            'uid' => -3,
            'role' => 'parent',
            'phone_key' => $sid,
            'sid' => $sid,
            'must_change_pass' => $par ? (bool)$par['must_change_pass'] : false,
            'session_id' => $session['id']
        ];
    }

    return null;
}

// دالة فحص النسخ التلقائي وتشغيله بناءً على بصمة SHA-1
function triggerAutoBackupIfNeeded($pdo, $prefix, $storeData, $ver) {
    try {
        $meta = $storeData['meta'] ?? [];
        $interval = $meta['backup_interval'] ?? 'daily';
        if ($interval === 'off') return;

        $hours = 24;
        if ($interval === '12h') $hours = 12;
        elseif ($interval === '2days') $hours = 48;
        elseif ($interval === 'weekly') $hours = 168;

        $lastBackup = $meta['last_backup_at'] ?? null;
        $nowTime = time();

        if ($lastBackup && ($nowTime - strtotime($lastBackup) < $hours * 3600)) {
            return; // لم يحن الموعد بعد
        }

        $jsonStr = json_encode($storeData, JSON_UNESCAPED_UNICODE);
        $currHash = sha1($jsonStr);
        $lastHash = $meta['last_data_hash'] ?? '';

        if ($currHash === $lastHash) {
            return; // لم تتغير البيانات
        }

        // إنشاء نسخة مضغوطة بواسطة gzdeflate
        $compressed = gzdeflate($jsonStr, 9);
        $nowStr = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("INSERT INTO `{$prefix}snaps` (snap_hash, data_gz, ver, created_at, created_by) VALUES (:h, :gz, :v, :t, 'نسخ تلقائي')");
        $stmt->execute([
            ':h' => $currHash,
            ':gz' => $compressed,
            ':v' => $ver,
            ':t' => $nowStr
        ]);

        // حذف النسخ القديمة بعد العدد المحدد
        $keepCount = max(5, (int)($meta['backup_keep_count'] ?? 10));
        $driver = defined('DB_DRIVER') ? strtolower(DB_DRIVER) : 'mysql';
        if ($driver === 'sqlite') {
            $pdo->exec("DELETE FROM `{$prefix}snaps` WHERE id NOT IN (SELECT id FROM `{$prefix}snaps` ORDER BY id DESC LIMIT {$keepCount})");
        } else {
            $pdo->exec("DELETE FROM `{$prefix}snaps` WHERE id NOT IN (SELECT id FROM (SELECT id FROM `{$prefix}snaps` ORDER BY id DESC LIMIT {$keepCount}) AS t)");
        }

        // حفظ نسخة ملف ثانية اختيارية في backups/ إذا كان المجلد متوفراً ومحمياً
        $backupDir = __DIR__ . '/backups';
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0755, true);
            @file_put_contents($backupDir . '/.htaccess', "Order allow,deny\nDeny from all\n");
        }
        if (is_dir($backupDir) && is_writable($backupDir)) {
            $fileGz = $backupDir . '/backup_' . date('Ymd_His') . '_v' . $ver . '.json.gz';
            @file_put_contents($fileGz, $compressed);
        }
    } catch (Exception $e) {}
}

// دمج بيانات المعلم مع المتجر الإجمالي
function mergeTeacherUpdates($currentStore, $incomingData, $user) {
    $allowedClasses = $user['classes'] ?? [];
    $allowedSubjects = $user['subjects'] ?? [];
    $perms = $user['permissions'] ?? [];

    // إذا كان مربي صف أو لديه صلاحيات محددة، ندمج فقط الأقسام المسموح بها
    if (!empty($perms['attendance'])) {
        $allowedSectionIds = [];
        foreach ($currentStore['sections'] as $sec) {
            if (in_array($sec['class_id'], $allowedClasses)) {
                $allowedSectionIds[] = $sec['id'];
            }
        }
        if (!empty($incomingData['attendance'])) {
            $retainedAttendance = array_filter($currentStore['attendance'] ?? [], function($att) use ($allowedSectionIds) {
                return !in_array($att['section_id'] ?? '', $allowedSectionIds);
            });
            $newTeacherAttendance = array_filter($incomingData['attendance'] ?? [], function($att) use ($allowedSectionIds) {
                return in_array($att['section_id'] ?? '', $allowedSectionIds);
            });
            $currentStore['attendance'] = array_values(array_merge($retainedAttendance, $newTeacherAttendance));
        }
    }

    if (!empty($perms['grades'])) {
        if (!empty($incomingData['grades'])) {
            $retainedGrades = array_filter($currentStore['grades'] ?? [], function($gr) use ($allowedSubjects) {
                return !in_array($gr['subject_id'] ?? '', $allowedSubjects);
            });
            $newTeacherGrades = array_filter($incomingData['grades'] ?? [], function($gr) use ($allowedSubjects) {
                return in_array($gr['subject_id'] ?? '', $allowedSubjects);
            });
            $currentStore['grades'] = array_values(array_merge($retainedGrades, $newTeacherGrades));
        }
    }

    if (!empty($perms['homework'])) {
        if (isset($incomingData['homework'])) {
            $retainedHw = array_filter($currentStore['homework'] ?? [], function($hw) use ($allowedClasses) {
                return !in_array($hw['class_id'] ?? '', $allowedClasses);
            });
            $newHw = array_filter($incomingData['homework'] ?? [], function($hw) use ($allowedClasses) {
                return in_array($hw['class_id'] ?? '', $allowedClasses);
            });
            $currentStore['homework'] = array_values(array_merge($retainedHw, $newHw));
        }
    }

    if (!empty($perms['plans'])) {
        if (isset($incomingData['plans'])) {
            $retainedPlans = array_filter($currentStore['plans'] ?? [], function($pl) use ($allowedSubjects) {
                return !in_array($pl['subject_id'] ?? '', $allowedSubjects);
            });
            $newPlans = array_filter($incomingData['plans'] ?? [], function($pl) use ($allowedSubjects) {
                return in_array($pl['subject_id'] ?? '', $allowedSubjects);
            });
            $currentStore['plans'] = array_values(array_merge($retainedPlans, $newPlans));
        }
    }

    if (!empty($perms['violations'])) {
        if (isset($incomingData['violations'])) {
            $currentStore['violations'] = $incomingData['violations'];
        }
    }

    if (!empty($perms['notes'])) {
        if (isset($incomingData['notes'])) {
            $currentStore['notes'] = $incomingData['notes'];
        }
    }

    return $currentStore;
}

// -------------------------------------------------------------------
// معالجة مسارات الـ API (Router)
// -------------------------------------------------------------------

$action = $_GET['a'] ?? $_POST['a'] ?? '';
$pdo = getDbConnection();
$driver = defined('DB_DRIVER') ? strtolower(DB_DRIVER) : 'mysql';
$prefix = defined('DB_PREFIX') ? DB_PREFIX : 'sc_';
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// قراءة محتوى الطلب JSON إن وُجد
$inputJson = file_get_contents('php://input');
$reqData = json_decode($inputJson, true) ?: $_POST;

switch ($action) {

    // ---------------------------------------------------------------
    // 1. الصفحة الرئيسية العامة ومعلومات الزوار (لا تتطلب مصادقة)
    // ---------------------------------------------------------------
    case 'public_info':
        $stmt = $pdo->prepare("SELECT val, updated_at FROM `{$prefix}public` WHERE id = 'home' LIMIT 1");
        $stmt->execute();
        $row = $stmt->fetch();
        $homeData = $row ? json_decode($row['val'], true) : [];

        // إحصائيات عامة فقط دون كشف أي بيانات شخصية
        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $storeRow = $stmtStore->fetch();
        $storeData = $storeRow ? json_decode($storeRow['data'], true) : [];

        $counts = [
            'students' => count($storeData['students'] ?? []),
            'classes' => count($storeData['classes'] ?? []),
            'sections' => count($storeData['sections'] ?? []),
            'subjects' => count($storeData['subjects'] ?? [])
        ];

        echo json_encode([
            'ok' => true,
            'home' => $homeData,
            'counts' => $counts,
            'server_time' => date('Y-m-d H:i:s')
        ], JSON_UNESCAPED_UNICODE);
        break;

    // حفظ تصميم الصفحة الرئيسية (للمسؤول فقط)
    case 'public_save':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized', 'message' => 'غير مصرح'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $homeDesign = $reqData['home'] ?? null;
        if (!$homeDesign) {
            echo json_encode(['ok' => false, 'error' => 'invalid_data'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $now = date('Y-m-d H:i:s');
        $jsonStr = json_encode($homeDesign, JSON_UNESCAPED_UNICODE);

        if ($driver === 'sqlite') {
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO `{$prefix}public` (id, val, updated_at) VALUES ('home', :v, :t)");
        } else {
            $stmt = $pdo->prepare("INSERT INTO `{$prefix}public` (id, val, updated_at) VALUES ('home', :v, :t) ON DUPLICATE KEY UPDATE val = VALUES(val), updated_at = VALUES(updated_at)");
        }
        $stmt->execute([':v' => $jsonStr, ':t' => $now]);

        logAudit($pdo, $prefix, 0, $user['username'], 'update_public_home', 'تحديث تصميم وإعدادات الصفحة العامة');

        echo json_encode(['ok' => true, 'message' => 'تم حفظ تصميم الصفحة بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 2. تسجيل الدخول الشامل (مدير، معلم، طالب، ولي أمر)
    // ---------------------------------------------------------------
    case 'login':
        $loginType = $reqData['type'] ?? 'staff'; // staff, student, parent
        $identifier = trim($reqData['username'] ?? $reqData['id'] ?? $reqData['phone'] ?? '');
        $password = (string)($reqData['password'] ?? '');

        // فحص القوة الغاشمة
        $bruteCheck = checkBruteForce($pdo, $prefix, $ip, $identifier);
        if ($bruteCheck['blocked']) {
            http_response_code(429);
            echo json_encode(['ok' => false, 'error' => 'blocked', 'message' => $bruteCheck['message']], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (empty($identifier) || empty($password)) {
            recordLoginAttempt($pdo, $prefix, $ip, $identifier, false);
            echo json_encode(['ok' => false, 'error' => 'invalid_credentials', 'message' => 'اسم المستخدم أو كلمة المرور غير صحيحة'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $authenticatedUser = null;
        $uid = null;
        $sid = '';

        if ($loginType === 'staff') {
            // أ. فحص حساب المدير العام في sc_auth
            $stmtAdmin = $pdo->prepare("SELECT id, username, pass_hash, is_default, email FROM `{$prefix}auth` WHERE id = 1 AND username = :u LIMIT 1");
            $stmtAdmin->execute([':u' => $identifier]);
            $admin = $stmtAdmin->fetch();

            if ($admin && password_verify($password, $admin['pass_hash'])) {
                $uid = 0;
                $authenticatedUser = [
                    'uid' => 0,
                    'role' => 'admin',
                    'username' => $admin['username'],
                    'full_name' => 'المدير العام',
                    'is_default' => (bool)$admin['is_default'],
                    'email' => $admin['email'],
                    'permissions' => ['all' => true]
                ];
            } else {
                // ب. فحص حسابات المعلمين والإداريين في sc_users
                $stmtStaff = $pdo->prepare("SELECT id, username, pass_hash, full_name, role, permissions, subjects, classes, active FROM `{$prefix}users` WHERE username = :u LIMIT 1");
                $stmtStaff->execute([':u' => $identifier]);
                $staff = $stmtStaff->fetch();

                if ($staff && $staff['active'] && password_verify($password, $staff['pass_hash'])) {
                    $uid = (int)$staff['id'];
                    $authenticatedUser = [
                        'uid' => $uid,
                        'role' => $staff['role'],
                        'username' => $staff['username'],
                        'full_name' => $staff['full_name'],
                        'permissions' => json_decode($staff['permissions'] ?: '{}', true),
                        'subjects' => json_decode($staff['subjects'] ?: '[]', true),
                        'classes' => json_decode($staff['classes'] ?: '[]', true)
                    ];
                }
            }
        } elseif ($loginType === 'student') {
            // ج. فحص دخول الطالب في sc_stu
            // يمكن للطالب الدخول برقم الطالب أو برقم الهوية
            $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
            $stmtStore->execute();
            $store = json_decode($stmtStore->fetchColumn() ?: '{}', true);

            $matchedStudent = null;
            foreach ($store['students'] ?? [] as $st) {
                if ($st['id'] == $identifier || ($st['national_id'] ?? '') == $identifier) {
                    $matchedStudent = $st;
                    break;
                }
            }

            if ($matchedStudent) {
                $stuId = $matchedStudent['id'];
                $stmtStu = $pdo->prepare("SELECT id, pass_hash, is_default, must_change_pass FROM `{$prefix}stu` WHERE id = :id LIMIT 1");
                $stmtStu->execute([':id' => $stuId]);
                $stuAuth = $stmtStu->fetch();

                // كلمة المرور الافتراضية إذا لم تُنشأ بعد هي آخر 6 أرقام من الهوية أو '123456'
                $valid = false;
                if ($stuAuth) {
                    $valid = password_verify($password, $stuAuth['pass_hash']);
                } else {
                    $defaultCandidate = substr($matchedStudent['national_id'] ?? '123456', -6);
                    if ($password === $defaultCandidate || $password === '123456') {
                        $valid = true;
                        // حفظ التجزئة تلقائياً
                        $hash = password_hash($password, PASSWORD_DEFAULT);
                        $pdo->prepare("INSERT INTO `{$prefix}stu` (id, pass_hash, is_default, must_change_pass, updated_at) VALUES (:id, :p, 1, 1, :t)")
                            ->execute([':id' => $stuId, ':p' => $hash, ':t' => date('Y-m-d H:i:s')]);
                        $stuAuth = ['is_default' => 1, 'must_change_pass' => 1];
                    }
                }

                if ($valid) {
                    $uid = -2;
                    $sid = $stuId;
                    $authenticatedUser = [
                        'uid' => -2,
                        'role' => 'student',
                        'student_id' => $stuId,
                        'student_name' => $matchedStudent['name'],
                        'class_id' => $matchedStudent['class_id'],
                        'section_id' => $matchedStudent['section_id'],
                        'must_change_pass' => (bool)($stuAuth['must_change_pass'] ?? false)
                    ];
                }
            }
        } elseif ($loginType === 'parent') {
            // د. فحص دخول ولي الأمر في sc_parents
            $phoneKey = normalizePhoneKey($identifier);
            if (!empty($phoneKey)) {
                $stmtPar = $pdo->prepare("SELECT phone_key, pass_hash, is_default, must_change_pass FROM `{$prefix}parents` WHERE phone_key = :pk LIMIT 1");
                $stmtPar->execute([':pk' => $phoneKey]);
                $parAuth = $stmtPar->fetch();

                $valid = false;
                if ($parAuth) {
                    $valid = password_verify($password, $parAuth['pass_hash']);
                } else {
                    // كلمة المرور الافتراضية إذا لم تكن مسجلة
                    if ($password === '123456' || $password === substr($phoneKey, -6)) {
                        $valid = true;
                        $hash = password_hash($password, PASSWORD_DEFAULT);
                        $pdo->prepare("INSERT INTO `{$prefix}parents` (phone_key, pass_hash, is_default, must_change_pass, updated_at) VALUES (:pk, :p, 1, 1, :t)")
                            ->execute([':pk' => $phoneKey, ':p' => $hash, ':t' => date('Y-m-d H:i:s')]);
                        $parAuth = ['is_default' => 1, 'must_change_pass' => 1];
                    }
                }

                if ($valid) {
                    $uid = -3;
                    $sid = $phoneKey;
                    $authenticatedUser = [
                        'uid' => -3,
                        'role' => 'parent',
                        'phone_key' => $phoneKey,
                        'must_change_pass' => (bool)($parAuth['must_change_pass'] ?? false)
                    ];
                }
            }
        }

        if (!$authenticatedUser) {
            recordLoginAttempt($pdo, $prefix, $ip, $identifier, false);
            echo json_encode(['ok' => false, 'error' => 'invalid_credentials', 'message' => 'اسم المستخدم أو كلمة المرور غير صحيحة'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // نجاح تسجيل الدخول: توليد التوكن
        recordLoginAttempt($pdo, $prefix, $ip, $identifier, true);

        $tokenRaw = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $tokenRaw);
        
        // صلاحية التوكن: 30 يوماً
        $expiresAt = date('Y-m-d H:i:s', time() + 30 * 86400);
        $now = date('Y-m-d H:i:s');

        $stmtInsTok = $pdo->prepare("INSERT INTO `{$prefix}tokens` (token_hash, expires_at, uid, sid, created_at) VALUES (:th, :exp, :uid, :sid, :t)");
        $stmtInsTok->execute([
            ':th' => $tokenHash,
            ':exp' => $expiresAt,
            ':uid' => $uid,
            ':sid' => $sid,
            ':t' => $now
        ]);

        logAudit($pdo, $prefix, $uid, $authenticatedUser['username'] ?? $identifier, 'login_success', "تسجيل دخول بنجاح ({$loginType})");

        echo json_encode([
            'ok' => true,
            'token' => $tokenRaw,
            'user' => $authenticatedUser,
            'expires_at' => $expiresAt
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 3. التحقق من صحة الجلسة الحالية (check_auth)
    // ---------------------------------------------------------------
    case 'check_auth':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            echo json_encode(['ok' => false, 'error' => 'unauthenticated'], JSON_UNESCAPED_UNICODE);
            exit;
        }
        echo json_encode(['ok' => true, 'user' => $user], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 4. تسجيل الخروج (logout)
    // ---------------------------------------------------------------
    case 'logout':
        $token = $_SERVER['HTTP_X_TOKEN'] ?? $_REQUEST['token'] ?? '';
        if ($token) {
            $tokenHash = hash('sha256', $token);
            $pdo->prepare("DELETE FROM `{$prefix}tokens` WHERE token_hash = :h")->execute([':h' => $tokenHash]);
        }
        echo json_encode(['ok' => true, 'message' => 'تم تسجيل الخروج بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 5. تغيير كلمة المرور (إجباري عند أول دخول أو اختياري)
    // ---------------------------------------------------------------
    case 'change_pass':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => 'unauthenticated'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $newPass = (string)($reqData['new_password'] ?? '');
        if (strlen($newPass) < 6) {
            echo json_encode(['ok' => false, 'error' => 'weak_password', 'message' => 'يجب أن تكون كلمة المرور 6 أحرف أو أرقام على الأقل'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $newHash = password_hash($newPass, PASSWORD_DEFAULT);
        $now = date('Y-m-d H:i:s');

        if ($user['uid'] === 0) {
            $pdo->prepare("UPDATE `{$prefix}auth` SET pass_hash = :p, is_default = 0, updated_at = :t WHERE id = 1")
                ->execute([':p' => $newHash, ':t' => $now]);
        } elseif ($user['uid'] > 0) {
            $pdo->prepare("UPDATE `{$prefix}users` SET pass_hash = :p WHERE id = :id")
                ->execute([':p' => $newHash, ':id' => $user['uid']]);
        } elseif ($user['uid'] === -2) {
            $pdo->prepare("UPDATE `{$prefix}stu` SET pass_hash = :p, is_default = 0, must_change_pass = 0, updated_at = :t WHERE id = :id")
                ->execute([':p' => $newHash, ':t' => $now, ':id' => $user['sid']]);
        } elseif ($user['uid'] === -3) {
            $pdo->prepare("UPDATE `{$prefix}parents` SET pass_hash = :p, is_default = 0, must_change_pass = 0, updated_at = :t WHERE phone_key = :pk")
                ->execute([':p' => $newHash, ':t' => $now, ':pk' => $user['sid']]);
        }

        logAudit($pdo, $prefix, $user['uid'], $user['username'] ?? $user['sid'], 'change_password', 'تغيير كلمة المرور بنجاح');

        echo json_encode(['ok' => true, 'message' => 'تم تغيير كلمة المرور بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 6. استعادة كلمة مرور المدير العام عبر البريد (sc_resets)
    // ---------------------------------------------------------------
    case 'forgot_pass':
        $username = trim($reqData['username'] ?? '');
        $stmtAdmin = $pdo->prepare("SELECT id, username, email FROM `{$prefix}auth` WHERE id = 1 AND username = :u LIMIT 1");
        $stmtAdmin->execute([':u' => $username]);
        $admin = $stmtAdmin->fetch();

        if (!$admin || empty($admin['email'])) {
            // رسالة حيادية لمنع تعداد المستخدمين
            echo json_encode(['ok' => true, 'message' => 'إذا كان اسم المستخدم صحيحاً ومربوطاً ببريد إلكتروني، فقد تم إرسال تعليمات الاستعادة.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $code = str_pad(mt_rand(100000, 999999), 6, '0', STR_PAD_LEFT);
        $tokenHash = hash('sha256', $code);
        $expires = date('Y-m-d H:i:s', time() + 1800); // 30 دقيقة
        $now = date('Y-m-d H:i:s');

        $pdo->prepare("INSERT INTO `{$prefix}resets` (token_hash, expires_at, created_at) VALUES (:th, :exp, :t)")
            ->execute([':th' => $tokenHash, ':exp' => $expires, ':t' => $now]);

        // محاولة إرسال البريد
        $subject = "رمز استعادة كلمة المرور — نظام إدارة المدرسة";
        $message = "مرحباً،\n\nرمز استعادة كلمة مرور حساب المسؤول الخاص بك هو: {$code}\nصلاحية هذا الرمز 30 دقيقة فقط.\n\nإذا لم تطلب ذلك، يُرجى تجاهل هذه الرسالة.";
        $headers = "From: noreply@" . ($_SERVER['SERVER_NAME'] ?? 'school.local') . "\r\nContent-Type: text/plain; charset=UTF-8";
        @mail($admin['email'], $subject, $message, $headers);

        logAudit($pdo, $prefix, 0, $username, 'forgot_pass_requested', 'طلب رمز استعادة كلمة المرور عبر البريد');

        $resp = ['ok' => true, 'message' => 'تم إرسال رمز الاستعادة إلى بريدك الإلكتروني المسجل.'];
        if (defined('DEBUG_SETUP') && DEBUG_SETUP) {
            $resp['debug_code'] = $code; // يظهر فقط في وضع التطوير
        }
        echo json_encode($resp, JSON_UNESCAPED_UNICODE);
        break;

    case 'reset_pass':
        $code = trim($reqData['code'] ?? '');
        $newPass = (string)($reqData['new_password'] ?? '');
        if (strlen($newPass) < 6) {
            echo json_encode(['ok' => false, 'error' => 'weak_password', 'message' => 'كلمة المرور يجب أن لا تقل عن 6 أحرف'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $tokenHash = hash('sha256', $code);
        $now = date('Y-m-d H:i:s');

        $stmt = $pdo->prepare("SELECT id FROM `{$prefix}resets` WHERE token_hash = :th AND expires_at > :now LIMIT 1");
        $stmt->execute([':th' => $tokenHash, ':now' => $now]);
        $resetRow = $stmt->fetch();

        if (!$resetRow) {
            echo json_encode(['ok' => false, 'error' => 'invalid_code', 'message' => 'رمز الاستعادة غير صحيح أو انتهت صلاحيته'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $newHash = password_hash($newPass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE `{$prefix}auth` SET pass_hash = :p, is_default = 0, updated_at = :t WHERE id = 1")
            ->execute([':p' => $newHash, ':t' => $now]);

        $pdo->prepare("DELETE FROM `{$prefix}resets` WHERE id = :id")->execute([':id' => $resetRow['id']]);

        logAudit($pdo, $prefix, 0, 'admin', 'reset_pass_completed', 'إعادة ضبط كلمة مرور المسؤول بنجاح');

        echo json_encode(['ok' => true, 'message' => 'تمت استعادة وتغيير كلمة المرور بنجاح. يمكنك الآن تسجيل الدخول.'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 7. جلب بيانات المدرسة الموحدة (get_data)
    // ---------------------------------------------------------------
    case 'get_data':
        $user = authenticate($pdo, $prefix);
        if (!$user || ($user['uid'] !== 0 && $user['uid'] <= 0)) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare("SELECT data, ver, updated_at FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmt->execute();
        $row = $stmt->fetch();
        $storeData = $row ? json_decode($row['data'], true) : [];
        $ver = $row ? (int)$row['ver'] : 1;

        // التحقق من النسخ الاحتياطي التلقائي مع حركة الموقع
        triggerAutoBackupIfNeeded($pdo, $prefix, $storeData, $ver);

        echo json_encode([
            'ok' => true,
            'ver' => $ver,
            'updated_at' => $row['updated_at'] ?? date('Y-m-d H:i:s'),
            'data' => $storeData
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 8. حفظ بيانات المدرسة مع القفل التفاؤلي ودمج صلاحيات المعلم (save_data)
    // ---------------------------------------------------------------
    case 'save_data':
        $user = authenticate($pdo, $prefix);
        if (!$user || ($user['uid'] !== 0 && $user['uid'] <= 0)) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $incomingVer = isset($reqData['ver']) ? (int)$reqData['ver'] : null;
        $incomingData = $reqData['data'] ?? null;

        if ($incomingData === null) {
            echo json_encode(['ok' => false, 'error' => 'no_data'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // جلب النسخة الحالية من الخادم للتحقق من القفل التفاؤلي
        $stmtCurrent = $pdo->prepare("SELECT data, ver FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtCurrent->execute();
        $currRow = $stmtCurrent->fetch();
        $serverVer = $currRow ? (int)$currRow['ver'] : 1;
        $serverData = $currRow ? json_decode($currRow['data'], true) : [];

        // إذا كان رقم نسخة المتصفح أقدم من الخادم، يُرفض الحفظ فوراً
        if ($incomingVer !== null && $incomingVer < $serverVer) {
            http_response_code(409); // Conflict
            echo json_encode([
                'ok' => false,
                'error' => 'conflict',
                'message' => 'تم تعديل البيانات وحفظها مسبقاً من قِبل مستخدم آخر. يرجى إعادة تحميل أحدث البيانات لدمج تعديلاتك.',
                'server_ver' => $serverVer
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // تحديد البيانات النهائية للحفظ:
        // إذا كان مدير: يحفظ كل شيء
        // إذا كان معلم: ندمج فقط الأقسام المصرح له بها
        if ($user['uid'] === 0) {
            $finalData = $incomingData;
        } else {
            $finalData = mergeTeacherUpdates($serverData, $incomingData, $user);
        }

        // تحديث البصمة وتاريخ النسخ في meta
        $newVer = $serverVer + 1;
        $now = date('Y-m-d H:i:s');
        $jsonFinal = json_encode($finalData, JSON_UNESCAPED_UNICODE);

        if ($driver === 'sqlite') {
            $stmtSave = $pdo->prepare("INSERT OR REPLACE INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t)");
        } else {
            $stmtSave = $pdo->prepare("INSERT INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t) ON DUPLICATE KEY UPDATE data = VALUES(data), ver = VALUES(ver), updated_at = VALUES(updated_at)");
        }
        $stmtSave->execute([
            ':d' => $jsonFinal,
            ':v' => $newVer,
            ':t' => $now
        ]);

        // فحص النسخ التلقائي
        triggerAutoBackupIfNeeded($pdo, $prefix, $finalData, $newVer);

        logAudit($pdo, $prefix, $user['uid'], $user['username'] ?? $user['full_name'], 'save_store_data', "حفظ بيانات المدرسة بنجاح (نسخة: {$newVer})");

        echo json_encode([
            'ok' => true,
            'ver' => $newVer,
            'updated_at' => $now,
            'message' => 'تم حفظ البيانات بنجاح'
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 9. بيانات بوابة الطالب (student_data) — تنقية شاملة للبيانات
    // ---------------------------------------------------------------
    case 'student_data':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['role'] !== 'student') {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $studentId = $user['sid'];
        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $store = json_decode($stmtStore->fetchColumn() ?: '{}', true);

        // العثور على الطالب وتجريد الحقول الحساسة
        $studentObj = null;
        foreach ($store['students'] ?? [] as $st) {
            if ($st['id'] == $studentId) {
                $studentObj = $st;
                break;
            }
        }

        if (!$studentObj) {
            echo json_encode(['ok' => false, 'error' => 'student_not_found'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // حذف الحقول الحساسة قطيعاً
        unset($studentObj['parent_national_id']);
        unset($studentObj['mother_name']);
        unset($studentObj['address']);

        // إعدادات البوابة المصرح بها
        $perms = $store['meta']['student_portal_perms'] ?? [
            'grades' => true, 'attendance' => true, 'violations' => true, 'notes' => true, 'homework' => true, 'schedule' => true
        ];

        // تصفية الحضور
        $attendance = [];
        if (!empty($perms['attendance'])) {
            $attendance = array_values(array_filter($store['attendance'] ?? [], function($a) use ($studentId) {
                return ($a['student_id'] ?? '') == $studentId;
            }));
        }

        // تصفية المخالفات
        $violations = [];
        if (!empty($perms['violations'])) {
            $violations = array_values(array_filter($store['violations'] ?? [], function($v) use ($studentId) {
                return ($v['student_id'] ?? '') == $studentId;
            }));
        }

        // تصفية الملاحظات: استبعاد الملاحظات الصحية والاجتماعية السرية تماماً!
        $notes = [];
        if (!empty($perms['notes'])) {
            $notes = array_values(array_filter($store['notes'] ?? [], function($n) use ($studentId) {
                $type = $n['type'] ?? 'general';
                return (($n['student_id'] ?? '') == $studentId) && ($type !== 'health' && $type !== 'social');
            }));
        }

        // تصفية العلامات
        $grades = [];
        if (!empty($perms['grades'])) {
            $grades = array_values(array_filter($store['grades'] ?? [], function($g) use ($studentId) {
                return ($g['student_id'] ?? '') == $studentId;
            }));
        }

        // تصفية الواجبات لشعبة الطالب
        $homework = [];
        if (!empty($perms['homework'])) {
            $homework = array_values(array_filter($store['homework'] ?? [], function($h) use ($studentObj) {
                return ($h['section_id'] ?? '') == $studentObj['section_id'] || ($h['class_id'] ?? '') == $studentObj['class_id'];
            }));
        }

        // جدول الحصص
        $schedule = [];
        if (!empty($perms['schedule'])) {
            $secId = $studentObj['section_id'] ?? '';
            $schedule = $store['schedule'][$secId] ?? [];
        }

        // العثور على نظام تقويم صف هذا الطالب
        $classId = $studentObj['class_id'] ?? '';
        $evalSystem = 'both';
        foreach ($store['classes'] ?? [] as $cls) {
            if ($cls['id'] == $classId) {
                $evalSystem = $cls['eval_system'] ?? 'both';
                break;
            }
        }

        echo json_encode([
            'ok' => true,
            'student' => $studentObj,
            'grades' => $grades,
            'attendance' => $attendance,
            'violations' => $violations,
            'notes' => $notes,
            'homework' => $homework,
            'schedule' => $schedule,
            'subjects' => $store['subjects'] ?? [],
            'grading_scales' => $store['grading_scales'] ?? [],
            'eval_system' => $evalSystem,
            'cert_config' => $store['cert_config'] ?? [],
            'school_name' => $store['meta']['school_name'] ?? 'مدرستي',
            'academic_year' => $store['meta']['academic_year'] ?? '2026/2027'
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 10. بيانات بوابة ولي الأمر (parent_data) — إظهار كافة الأبناء
    // ---------------------------------------------------------------
    case 'parent_data':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['role'] !== 'parent') {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $phoneKey = $user['sid'];
        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $store = json_decode($stmtStore->fetchColumn() ?: '{}', true);

        // العثور على جميع الأبناء المرتبطين برقم الهاتف هذا
        $children = [];
        foreach ($store['students'] ?? [] as $st) {
            $p1 = normalizePhoneKey($st['parent_phone'] ?? '');
            $p2 = normalizePhoneKey($st['phone2'] ?? '');
            $p3 = normalizePhoneKey($st['phone3'] ?? '');

            if ($p1 === $phoneKey || $p2 === $phoneKey || $p3 === $phoneKey) {
                $c = $st;
                // حذف الحقول الحساسة
                unset($c['parent_national_id']);
                unset($c['mother_name']);
                unset($c['address']);
                $children[] = $c;
            }
        }

        // تجهيز بيانات كل ابن على حدة
        $childrenData = [];
        foreach ($children as $ch) {
            $cid = $ch['id'];
            $secId = $ch['section_id'] ?? '';
            $classId = $ch['class_id'] ?? '';

            // نظام تقويم الصف
            $evalSys = 'both';
            foreach ($store['classes'] ?? [] as $cls) {
                if ($cls['id'] == $classId) {
                    $evalSys = $cls['eval_system'] ?? 'both';
                    break;
                }
            }

            $grades = array_values(array_filter($store['grades'] ?? [], function($g) use ($cid) {
                return ($g['student_id'] ?? '') == $cid;
            }));

            $attendance = array_values(array_filter($store['attendance'] ?? [], function($a) use ($cid) {
                return ($a['student_id'] ?? '') == $cid;
            }));

            $violations = array_values(array_filter($store['violations'] ?? [], function($v) use ($cid) {
                return ($v['student_id'] ?? '') == $cid;
            }));

            // الملاحظات: غير السرية فقط (استبعاد health و social)
            $notes = array_values(array_filter($store['notes'] ?? [], function($n) use ($cid) {
                $type = $n['type'] ?? 'general';
                return (($n['student_id'] ?? '') == $cid) && ($type !== 'health' && $type !== 'social');
            }));

            $homework = array_values(array_filter($store['homework'] ?? [], function($h) use ($secId, $classId) {
                return ($h['section_id'] ?? '') == $secId || ($h['class_id'] ?? '') == $classId;
            }));

            $childrenData[] = [
                'profile' => $ch,
                'eval_system' => $evalSys,
                'grades' => $grades,
                'attendance' => $attendance,
                'violations' => $violations,
                'notes' => $notes,
                'homework' => $homework,
                'schedule' => $store['schedule'][$secId] ?? []
            ];
        }

        echo json_encode([
            'ok' => true,
            'children' => $childrenData,
            'subjects' => $store['subjects'] ?? [],
            'grading_scales' => $store['grading_scales'] ?? [],
            'cert_config' => $store['cert_config'] ?? [],
            'school_name' => $store['meta']['school_name'] ?? 'مدرستي',
            'academic_year' => $store['meta']['academic_year'] ?? '2026/2027'
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 11. إدارة حسابات أولياء الأمور والطلاب (فتح دفعة واحدة / تصدير)
    // ---------------------------------------------------------------
    case 'parent_accounts_init':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $store = json_decode($stmtStore->fetchColumn() ?: '{}', true);

        // تجميع هواتف أولياء الأمور الفريدة
        $parentsList = [];
        foreach ($store['students'] ?? [] as $st) {
            $pk = normalizePhoneKey($st['parent_phone'] ?? '');
            if (!empty($pk)) {
                if (!isset($parentsList[$pk])) {
                    $parentsList[$pk] = [
                        'phone_key' => $pk,
                        'phone' => $st['parent_phone'],
                        'parent_name' => $st['parent_name'] ?? 'ولي أمر',
                        'students' => []
                    ];
                }
                $parentsList[$pk]['students'][] = $st['name'];
            }
        }

        // حروف واضحة لكلمات المرور العشوائية الخالية من التشابه
        $chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $now = date('Y-m-d H:i:s');
        $createdAccounts = [];

        foreach ($parentsList as $pk => $info) {
            $stmtEx = $pdo->prepare("SELECT phone_key FROM `{$prefix}parents` WHERE phone_key = :pk LIMIT 1");
            $stmtEx->execute([':pk' => $pk]);
            if ($stmtEx->fetch()) {
                continue; // الحساب موجود مسبقاً
            }

            // توليد كلمة مرور سهلة القراءة
            $passPlain = '';
            for ($i = 0; $i < 6; $i++) {
                $passPlain .= $chars[mt_rand(0, strlen($chars) - 1)];
            }
            $hash = password_hash($passPlain, PASSWORD_DEFAULT);

            $stmtIns = $pdo->prepare("INSERT INTO `{$prefix}parents` (phone_key, pass_hash, is_default, must_change_pass, updated_at) VALUES (:pk, :p, 1, 1, :t)");
            $stmtIns->execute([':pk' => $pk, ':p' => $hash, ':t' => $now]);

            $createdAccounts[] = [
                'phone_key' => $pk,
                'phone' => $info['phone'],
                'parent_name' => $info['parent_name'],
                'students' => implode('، ', $info['students']),
                'temp_password' => $passPlain
            ];
        }

        logAudit($pdo, $prefix, 0, $user['username'], 'parents_accounts_mass_init', "إنشاء " . count($createdAccounts) . " حساب ولي أمر جديد");

        echo json_encode([
            'ok' => true,
            'created_count' => count($createdAccounts),
            'accounts' => $createdAccounts
        ], JSON_UNESCAPED_UNICODE);
        break;

    case 'student_accounts_init':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $store = json_decode($stmtStore->fetchColumn() ?: '{}', true);

        $chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $now = date('Y-m-d H:i:s');
        $createdStudents = [];

        foreach ($store['students'] ?? [] as $st) {
            $sid = $st['id'];
            $stmtEx = $pdo->prepare("SELECT id FROM `{$prefix}stu` WHERE id = :id LIMIT 1");
            $stmtEx->execute([':id' => $sid]);
            if ($stmtEx->fetch()) {
                continue;
            }

            $passPlain = '';
            for ($i = 0; $i < 6; $i++) {
                $passPlain .= $chars[mt_rand(0, strlen($chars) - 1)];
            }
            $hash = password_hash($passPlain, PASSWORD_DEFAULT);

            $stmtIns = $pdo->prepare("INSERT INTO `{$prefix}stu` (id, pass_hash, is_default, must_change_pass, updated_at) VALUES (:id, :p, 1, 1, :t)");
            $stmtIns->execute([':id' => $sid, ':p' => $hash, ':t' => $now]);

            $createdStudents[] = [
                'id' => $sid,
                'name' => $st['name'],
                'national_id' => $st['national_id'] ?? '',
                'temp_password' => $passPlain
            ];
        }

        logAudit($pdo, $prefix, 0, $user['username'], 'students_accounts_mass_init', "إنشاء " . count($createdStudents) . " حساب طالب جديد");

        echo json_encode([
            'ok' => true,
            'created_count' => count($createdStudents),
            'accounts' => $createdStudents
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 12. إدارة المعلمين والمستخدمين (sc_users)
    // ---------------------------------------------------------------
    case 'users_list':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, username, full_name, role, permissions, subjects, classes, active, created_at FROM `{$prefix}users` ORDER BY id DESC");
        $stmt->execute();
        $users = $stmt->fetchAll();

        foreach ($users as &$u) {
            $u['permissions'] = json_decode($u['permissions'] ?: '{}', true);
            $u['subjects'] = json_decode($u['subjects'] ?: '[]', true);
            $u['classes'] = json_decode($u['classes'] ?: '[]', true);
        }

        echo json_encode(['ok' => true, 'users' => $users], JSON_UNESCAPED_UNICODE);
        break;

    case 'user_save':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $uId = isset($reqData['id']) ? (int)$reqData['id'] : 0;
        $uName = trim($reqData['username'] ?? '');
        $fName = trim($reqData['full_name'] ?? '');
        $uRole = trim($reqData['role'] ?? 'teacher');
        $uPass = (string)($reqData['password'] ?? '');
        $perms = json_encode($reqData['permissions'] ?? [], JSON_UNESCAPED_UNICODE);
        $subs = json_encode($reqData['subjects'] ?? [], JSON_UNESCAPED_UNICODE);
        $classes = json_encode($reqData['classes'] ?? [], JSON_UNESCAPED_UNICODE);
        $active = isset($reqData['active']) ? (int)$reqData['active'] : 1;

        if (empty($uName) || empty($fName)) {
            echo json_encode(['ok' => false, 'error' => 'missing_fields', 'message' => 'يرجى ملء كافة الحقول الإلزامية'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        if ($uId > 0) {
            // تحديث مستخدم حالي
            if (!empty($uPass)) {
                $hash = password_hash($uPass, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE `{$prefix}users` SET username = :u, pass_hash = :p, full_name = :f, role = :r, permissions = :perm, subjects = :sub, classes = :cls, active = :act WHERE id = :id");
                $stmt->execute([':u' => $uName, ':p' => $hash, ':f' => $fName, ':r' => $uRole, ':perm' => $perms, ':sub' => $subs, ':cls' => $classes, ':act' => $active, ':id' => $uId]);
            } else {
                $stmt = $pdo->prepare("UPDATE `{$prefix}users` SET username = :u, full_name = :f, role = :r, permissions = :perm, subjects = :sub, classes = :cls, active = :act WHERE id = :id");
                $stmt->execute([':u' => $uName, ':f' => $fName, ':r' => $uRole, ':perm' => $perms, ':sub' => $subs, ':cls' => $classes, ':act' => $active, ':id' => $uId]);
            }
            logAudit($pdo, $prefix, 0, $user['username'], 'update_user', "تعديل بيانات المستخدم {$uName}");
        } else {
            // إضافة مستخدم جديد
            if (empty($uPass)) {
                $uPass = '123456';
            }
            $hash = password_hash($uPass, PASSWORD_DEFAULT);
            $now = date('Y-m-d H:i:s');
            $stmt = $pdo->prepare("INSERT INTO `{$prefix}users` (username, pass_hash, full_name, role, permissions, subjects, classes, active, created_at) VALUES (:u, :p, :f, :r, :perm, :sub, :cls, :act, :t)");
            $stmt->execute([':u' => $uName, ':p' => $hash, ':f' => $fName, ':r' => $uRole, ':perm' => $perms, ':sub' => $subs, ':cls' => $classes, ':act' => $active, ':t' => $now]);
            logAudit($pdo, $prefix, 0, $user['username'], 'create_user', "إنشاء مستخدم جديد {$uName}");
        }

        echo json_encode(['ok' => true, 'message' => 'تم حفظ بيانات المستخدم بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    case 'user_delete':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $delId = (int)($reqData['id'] ?? 0);
        if ($delId > 0) {
            $pdo->prepare("DELETE FROM `{$prefix}users` WHERE id = :id")->execute([':id' => $delId]);
            $pdo->prepare("DELETE FROM `{$prefix}tokens` WHERE uid = :uid")->execute([':uid' => $delId]);
            logAudit($pdo, $prefix, 0, $user['username'], 'delete_user', "حذف المستخدم رقم {$delId}");
        }
        echo json_encode(['ok' => true, 'message' => 'تم حذف المستخدم بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 13. الجلسات الفعالة والإخراج الجماعي (sc_tokens)
    // ---------------------------------------------------------------
    case 'sessions_list':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $now = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            SELECT 
                SUM(CASE WHEN uid = 0 THEN 1 ELSE 0 END) AS admin_sessions,
                SUM(CASE WHEN uid > 0 THEN 1 ELSE 0 END) AS teacher_sessions,
                SUM(CASE WHEN uid = -2 THEN 1 ELSE 0 END) AS student_sessions,
                SUM(CASE WHEN uid = -3 THEN 1 ELSE 0 END) AS parent_sessions,
                COUNT(*) AS total_sessions
            FROM `{$prefix}tokens` 
            WHERE expires_at > :now
        ");
        $stmt->execute([':now' => $now]);
        $counts = $stmt->fetch();

        echo json_encode(['ok' => true, 'counts' => $counts], JSON_UNESCAPED_UNICODE);
        break;

    case 'sessions_kill':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $target = $reqData['target'] ?? 'all'; // all, teachers, students, parents
        $currentTokenHash = hash('sha256', $_SERVER['HTTP_X_TOKEN'] ?? '');

        if ($target === 'teachers') {
            $pdo->exec("DELETE FROM `{$prefix}tokens` WHERE uid > 0");
        } elseif ($target === 'students') {
            $pdo->exec("DELETE FROM `{$prefix}tokens` WHERE uid = -2");
        } elseif ($target === 'parents') {
            $pdo->exec("DELETE FROM `{$prefix}tokens` WHERE uid = -3");
        } else {
            // إخراج الجميع ما عدا جلسة المسؤول الحالية
            $stmt = $pdo->prepare("DELETE FROM `{$prefix}tokens` WHERE token_hash != :th");
            $stmt->execute([':th' => $currentTokenHash]);
        }

        logAudit($pdo, $prefix, 0, $user['username'], 'kill_sessions', "إنهاء الجلسات الجماعية: {$target}");

        echo json_encode(['ok' => true, 'message' => "تم تسجيل خروج الجلسات بنجاح ({$target})"], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 14. التواجد الحي الآن (Presence)
    // ---------------------------------------------------------------
    case 'presence_ping':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            echo json_encode(['ok' => false], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $sessId = (string)($user['session_id'] ?? 'sess_' . $user['uid']);
        $now = date('Y-m-d H:i:s');
        $uName = $user['username'] ?? $user['full_name'] ?? $user['sid'] ?? 'مستخدم';
        $role = $user['role'] ?? 'user';

        if ($driver === 'sqlite') {
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO `{$prefix}presence` (session_id, uid, user_name, role, last_seen) VALUES (:s, :u, :n, :r, :t)");
        } else {
            $stmt = $pdo->prepare("INSERT INTO `{$prefix}presence` (session_id, uid, user_name, role, last_seen) VALUES (:s, :u, :n, :r, :t) ON DUPLICATE KEY UPDATE user_name = VALUES(user_name), role = VALUES(role), last_seen = VALUES(last_seen)");
        }
        $stmt->execute([':s' => $sessId, ':u' => $user['uid'], ':n' => $uName, ':r' => $role, ':t' => $now]);

        // تنظيف المتواجدين الخاملين (> 3 دقائق)
        $threeMinAgo = date('Y-m-d H:i:s', time() - 180);
        $pdo->prepare("DELETE FROM `{$prefix}presence` WHERE last_seen < :t")->execute([':t' => $threeMinAgo]);

        echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
        break;

    case 'presence_list':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            http_response_code(401);
            echo json_encode(['ok' => false], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $threeMinAgo = date('Y-m-d H:i:s', time() - 180);
        $stmt = $pdo->prepare("SELECT user_name, role, last_seen FROM `{$prefix}presence` WHERE last_seen >= :t ORDER BY last_seen DESC");
        $stmt->execute([':t' => $threeMinAgo]);
        $online = $stmt->fetchAll();

        echo json_encode(['ok' => true, 'online_users' => $online, 'count' => count($online)], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 15. المراسلات الداخلية (sc_pm)
    // ---------------------------------------------------------------
    case 'pm_list':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            http_response_code(401);
            echo json_encode(['ok' => false], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $uid = $user['uid'];
        $stmt = $pdo->prepare("SELECT id, sender_uid, sender_name, subject, body, is_read, created_at FROM `{$prefix}pm` WHERE receiver_uid = :uid ORDER BY id DESC LIMIT 50");
        $stmt->execute([':uid' => $uid]);
        $messages = $stmt->fetchAll();

        // حساب عدد غير المقروءة
        $unread = 0;
        foreach ($messages as $m) {
            if (!$m['is_read']) $unread++;
        }

        echo json_encode(['ok' => true, 'messages' => $messages, 'unread_count' => $unread], JSON_UNESCAPED_UNICODE);
        break;

    case 'pm_send':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            http_response_code(401);
            echo json_encode(['ok' => false], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $receiverUid = (int)($reqData['receiver_uid'] ?? 0);
        $subject = trim($reqData['subject'] ?? 'بدون عنوان');
        $body = trim($reqData['body'] ?? '');
        $senderName = $user['full_name'] ?? $user['username'] ?? 'مستخدم';
        $now = date('Y-m-d H:i:s');

        if (empty($body)) {
            echo json_encode(['ok' => false, 'error' => 'empty_body'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare("INSERT INTO `{$prefix}pm` (sender_uid, sender_name, receiver_uid, subject, body, is_read, created_at) VALUES (:su, :sn, :ru, :sb, :b, 0, :t)");
        $stmt->execute([':su' => $user['uid'], ':sn' => $senderName, ':ru' => $receiverUid, ':sb' => $subject, ':b' => $body, ':t' => $now]);

        echo json_encode(['ok' => true, 'message' => 'تم إرسال الرسالة بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    case 'pm_mark_read':
        $user = authenticate($pdo, $prefix);
        if (!$user) {
            http_response_code(401);
            exit;
        }
        $msgId = (int)($reqData['id'] ?? 0);
        $pdo->prepare("UPDATE `{$prefix}pm` SET is_read = 1 WHERE id = :id AND receiver_uid = :uid")
            ->execute([':id' => $msgId, ':uid' => $user['uid']]);
        echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 16. سجل التدقيق الأمني (sc_audit)
    // ---------------------------------------------------------------
    case 'audit_list':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $search = trim($_GET['q'] ?? '');
        if ($search !== '') {
            $stmt = $pdo->prepare("SELECT * FROM `{$prefix}audit` WHERE action LIKE :s OR user_name LIKE :s OR details LIKE :s ORDER BY id DESC LIMIT 100");
            $stmt->execute([':s' => "%{$search}%"]);
        } else {
            $stmt = $pdo->prepare("SELECT * FROM `{$prefix}audit` ORDER BY id DESC LIMIT 100");
            $stmt->execute();
        }
        $logs = $stmt->fetchAll();

        echo json_encode(['ok' => true, 'logs' => $logs], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 17. النسخ الاحتياطي (sc_snaps) وإدارته الشاملة
    // ---------------------------------------------------------------
    case 'backups_list':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, snap_hash, ver, created_at, created_by, LENGTH(data_gz) as size_bytes FROM `{$prefix}snaps` ORDER BY id DESC");
        $stmt->execute();
        $snaps = $stmt->fetchAll();

        echo json_encode(['ok' => true, 'backups' => $snaps], JSON_UNESCAPED_UNICODE);
        break;

    case 'backup_create':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmtStore = $pdo->prepare("SELECT data, ver FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $row = $stmtStore->fetch();
        $dataStr = $row['data'] ?? '{}';
        $ver = (int)($row['ver'] ?? 1);

        $compressed = gzdeflate($dataStr, 9);
        $hash = sha1($dataStr);
        $now = date('Y-m-d H:i:s');
        $creator = $user['username'] ?? 'المدير';

        $stmt = $pdo->prepare("INSERT INTO `{$prefix}snaps` (snap_hash, data_gz, ver, created_at, created_by) VALUES (:h, :gz, :v, :t, :c)");
        $stmt->execute([':h' => $hash, ':gz' => $compressed, ':v' => $ver, ':t' => $now, ':c' => $creator]);

        logAudit($pdo, $prefix, 0, $user['username'], 'manual_backup_created', "إنشاء نسخة احتياطية يدوية برقم نسخة {$ver}");

        echo json_encode(['ok' => true, 'message' => 'تم إنشاء النسخة الاحتياطية بنجاح'], JSON_UNESCAPED_UNICODE);
        break;

    case 'backup_download':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            exit;
        }

        $snapId = (int)($_GET['id'] ?? 0);
        $stmt = $pdo->prepare("SELECT data_gz, ver, created_at FROM `{$prefix}snaps` WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $snapId]);
        $snap = $stmt->fetch();

        if (!$snap) {
            http_response_code(404);
            echo "النسخة غير موجودة";
            exit;
        }

        $uncompressed = gzinflate($snap['data_gz']);
        $filename = "school_backup_" . date('Ymd_His', strtotime($snap['created_at'])) . "_v" . $snap['ver'] . ".json";

        header('Content-Type: application/json; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"{$filename}\"");
        echo $uncompressed;
        exit;

    case 'backup_restore':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $snapId = (int)($reqData['id'] ?? 0);
        $stmt = $pdo->prepare("SELECT data_gz, ver FROM `{$prefix}snaps` WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $snapId]);
        $snap = $stmt->fetch();

        if (!$snap) {
            echo json_encode(['ok' => false, 'error' => 'not_found', 'message' => 'النسخة الاحتياطية غير موجودة'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // 1. أخذ نسخة تلقائية من الوضع الحالي قبل الاستعادة لحماية البيانات من أي فقدان
        $stmtCurrent = $pdo->prepare("SELECT data, ver FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtCurrent->execute();
        $currRow = $stmtCurrent->fetch();
        if ($currRow) {
            $curGz = gzdeflate($currRow['data'], 9);
            $curHash = sha1($currRow['data']);
            $now = date('Y-m-d H:i:s');
            $pdo->prepare("INSERT INTO `{$prefix}snaps` (snap_hash, data_gz, ver, created_at, created_by) VALUES (:h, :gz, :v, :t, 'قبل الاستعادة')")
                ->execute([':h' => $curHash, ':gz' => $curGz, ':v' => $currRow['ver'], ':t' => $now]);
        }

        // 2. فك الضغط وتطبيق النسخة
        $restoredJson = gzinflate($snap['data_gz']);
        $newVer = ((int)$snap['ver']) + 1;
        $now = date('Y-m-d H:i:s');

        if ($driver === 'sqlite') {
            $stmtApply = $pdo->prepare("INSERT OR REPLACE INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t)");
        } else {
            $stmtApply = $pdo->prepare("INSERT INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t) ON DUPLICATE KEY UPDATE data = VALUES(data), ver = VALUES(ver), updated_at = VALUES(updated_at)");
        }
        $stmtApply->execute([':d' => $restoredJson, ':v' => $newVer, ':t' => $now]);

        logAudit($pdo, $prefix, 0, $user['username'], 'backup_restored', "استعادة النسخة الاحتياطية رقم {$snapId} (نسخة جديدة: {$newVer})");

        echo json_encode(['ok' => true, 'message' => 'تمت استعادة النسخة الاحتياطية بنجاح', 'ver' => $newVer], JSON_UNESCAPED_UNICODE);
        break;

    case 'backup_delete':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            exit;
        }
        $delSnapId = (int)($reqData['id'] ?? 0);
        $pdo->prepare("DELETE FROM `{$prefix}snaps` WHERE id = :id")->execute([':id' => $delSnapId]);
        logAudit($pdo, $prefix, 0, $user['username'], 'backup_deleted', "حذف النسخة الاحتياطية رقم {$delSnapId}");
        echo json_encode(['ok' => true, 'message' => 'تم حذف النسخة الاحتياطية'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 18. بداية عام دراسي جديد (New Academic Year Roll)
    // ---------------------------------------------------------------
    case 'new_year_roll':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $newYearName = trim($reqData['new_academic_year'] ?? '2027/2028');
        $promotionMap = $reqData['promotion_map'] ?? []; // ['c1' => 'c2', 'c2' => 'c3', ...]
        $retainFailed = !empty($reqData['retain_failed']);
        $clearGrades = !empty($reqData['clear_grades']);
        $clearAttendance = !empty($reqData['clear_attendance']);
        $clearViolations = !empty($reqData['clear_violations']);
        $clearHomework = !empty($reqData['clear_homework']);

        // 1. أخذ نسخة احتياطية فورية على الخادم قبل الترحيل
        $stmtStore = $pdo->prepare("SELECT data, ver FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $currRow = $stmtStore->fetch();
        $store = json_decode($currRow['data'] ?? '{}', true);

        $curGz = gzdeflate($currRow['data'], 9);
        $curHash = sha1($currRow['data']);
        $now = date('Y-m-d H:i:s');
        $pdo->prepare("INSERT INTO `{$prefix}snaps` (snap_hash, data_gz, ver, created_at, created_by) VALUES (:h, :gz, :v, :t, 'أرشيف نهاية العام')")
            ->execute([':h' => $curHash, ':gz' => $curGz, ':v' => $currRow['ver'], ':t' => $now]);

        // 2. تحديد الطلاب الراسبين إن طُلب إبقاؤهم
        $failedStudentIds = [];
        if ($retainFailed) {
            // حساب الطلاب الذين رسبوا بأكثر من الحد المسموح به
            $passMark = (int)($store['cert_config']['pass_mark'] ?? 50);
            $maxIncomplete = (int)($store['cert_config']['max_incomplete'] ?? 2);
            $studentFails = [];
            foreach ($store['grades'] ?? [] as $gr) {
                $sid = $gr['student_id'] ?? '';
                $tot = (float)($gr['total'] ?? 0);
                if ($tot < $passMark) {
                    $studentFails[$sid] = ($studentFails[$sid] ?? 0) + 1;
                }
            }
            foreach ($studentFails as $sid => $failCount) {
                if ($failCount > $maxIncomplete) {
                    $failedStudentIds[] = $sid;
                }
            }
        }

        // 3. ترفيع الطلاب ونقل خريجي الصف الأخير إلى 'الخريجون <السنة>'
        $oldYear = $store['meta']['academic_year'] ?? '2026/2027';
        $gradSectionName = "الخريجون {$oldYear}";

        foreach ($store['students'] ?? [] as &$st) {
            $sid = $st['id'];
            if ($retainFailed && in_array($sid, $failedStudentIds)) {
                continue; // إبقاء الطالب الراسب في صفه
            }

            $currClassId = $st['class_id'] ?? '';
            $targetClassId = $promotionMap[$currClassId] ?? null;

            if ($targetClassId === 'graduates' || empty($targetClassId)) {
                $st['class_id'] = 'graduates';
                $st['section_id'] = 'graduates';
            } else {
                $st['class_id'] = $targetClassId;
                // إعادة تعيين الشعبة إلى الشعبة الأولى في الصف الجديد
                $newSec = null;
                foreach ($store['sections'] ?? [] as $sec) {
                    if ($sec['class_id'] == $targetClassId) {
                        $newSec = $sec['id'];
                        break;
                    }
                }
                $st['section_id'] = $newSec ?: $st['section_id'];
            }
        }

        // 4. مسح البيانات المحددة
        if ($clearGrades) $store['grades'] = [];
        if ($clearAttendance) $store['attendance'] = [];
        if ($clearViolations) $store['violations'] = [];
        if ($clearHomework) $store['homework'] = [];

        // 5. تحديث العام الدراسي
        $store['meta']['academic_year'] = $newYearName;

        // حفظ المتجر
        $newVer = ((int)$currRow['ver']) + 1;
        $jsonNew = json_encode($store, JSON_UNESCAPED_UNICODE);

        if ($driver === 'sqlite') {
            $stmtSave = $pdo->prepare("INSERT OR REPLACE INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t)");
        } else {
            $stmtSave = $pdo->prepare("INSERT INTO `{$prefix}store` (id, data, ver, updated_at) VALUES (1, :d, :v, :t) ON DUPLICATE KEY UPDATE data = VALUES(data), ver = VALUES(ver), updated_at = VALUES(updated_at)");
        }
        $stmtSave->execute([':d' => $jsonNew, ':v' => $newVer, ':t' => $now]);

        logAudit($pdo, $prefix, 0, $user['username'], 'new_year_roll', "ترحيل وبداية عام دراسي جديد: {$newYearName}");

        echo json_encode([
            'ok' => true,
            'message' => "تم ترحيل الطلاب وبدء العام الدراسي الجديد {$newYearName} بنجاح",
            'ver' => $newVer
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 19. فحص الأمان وقائمة الفحص (Security Checklist)
    // ---------------------------------------------------------------
    case 'security_check':
        $user = authenticate($pdo, $prefix);
        if (!$user || $user['uid'] !== 0) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'unauthorized'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // فحص بنود الأمان الـ 8
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? 0) == 443;
        
        $stmtAdmin = $pdo->prepare("SELECT is_default, email FROM `{$prefix}auth` WHERE id = 1 LIMIT 1");
        $stmtAdmin->execute();
        $admin = $stmtAdmin->fetch();
        $isDefaultPass = $admin ? (bool)$admin['is_default'] : false;
        $hasRecoveryEmail = $admin && !empty($admin['email']);

        $debugOff = !(defined('DEBUG_SETUP') && DEBUG_SETUP);
        $htaccessExists = file_exists(__DIR__ . '/.htaccess');
        $noVisibleErrorLog = !file_exists(__DIR__ . '/error_log');

        $stmtStore = $pdo->prepare("SELECT data FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $st = json_decode($stmtStore->fetchColumn() ?: '{}', true);

        $autoLogoutActive = ((int)($st['meta']['auto_logout_minutes'] ?? 60)) > 0;
        $autoBackupActive = ($st['meta']['backup_interval'] ?? 'daily') !== 'off';

        $checklist = [
            ['title' => 'الموقع يعمل عبر اتصال مشفر HTTPS', 'status' => $isHttps],
            ['title' => 'كلمة مرور المسؤول ليست الافتراضية', 'status' => !$isDefaultPass],
            ['title' => 'بريد استرداد كلمة المرور مضبوط', 'status' => $hasRecoveryEmail],
            ['title' => 'وضع التشخيص DEBUG متوقف', 'status' => $debugOff],
            ['title' => 'ملف الحماية .htaccess موجود وفعال', 'status' => $htaccessExists],
            ['title' => 'لا يوجد ملف error_log ظاهر ومكشوف', 'status' => $noVisibleErrorLog],
            ['title' => 'الخروج التلقائي عند الخمول مفعّل', 'status' => $autoLogoutActive],
            ['title' => 'النسخ الاحتياطي التلقائي مفعّل', 'status' => $autoBackupActive],
        ];

        echo json_encode([
            'ok' => true,
            'checklist' => $checklist,
            'server_info' => [
                'php_version' => PHP_VERSION,
                'db_driver' => $driver,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'PHP CLI'
            ]
        ], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 20. مهمة Cron للنسخ الاحتياطي المجدول عبر الخادم
    // ---------------------------------------------------------------
    case 'cron':
        $providedKey = $_GET['key'] ?? '';
        $expectedKey = defined('CRON_KEY') ? CRON_KEY : '';

        if (empty($expectedKey) || $providedKey !== $expectedKey) {
            http_response_code(403);
            echo json_encode(['ok' => false, 'error' => 'invalid_cron_key'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $stmtStore = $pdo->prepare("SELECT data, ver FROM `{$prefix}store` WHERE id = 1 LIMIT 1");
        $stmtStore->execute();
        $row = $stmtStore->fetch();
        $store = json_decode($row['data'] ?? '{}', true);
        $ver = (int)($row['ver'] ?? 1);

        triggerAutoBackupIfNeeded($pdo, $prefix, $store, $ver);

        echo json_encode(['ok' => true, 'message' => 'Cron backup checked/completed'], JSON_UNESCAPED_UNICODE);
        break;

    // ---------------------------------------------------------------
    // 21. فحص الاتصال البسيط (Ping)
    // ---------------------------------------------------------------
    case 'ping':
        echo json_encode([
            'ok' => true,
            'status' => 'online',
            'time' => date('Y-m-d H:i:s')
        ], JSON_UNESCAPED_UNICODE);
        break;

    default:
        echo json_encode([
            'ok' => false,
            'error' => 'unknown_action',
            'message' => 'العملية المطلوبة غير معرفة في الخادم'
        ], JSON_UNESCAPED_UNICODE);
        break;
}
