-- ===================================================================
-- نظام إدارة المدرسة المتكامل — هيكل قاعدة البيانات (database.sql)
-- متوافق مع MySQL 5.7+ و 8.0+ / MariaDB 10.2+
-- ترميز الأحرف: utf8mb4_unicode_ci للدعم العربي الكامل
-- ===================================================================

SET FOREIGN_KEY_CHECKS = 0;
SET NAMES utf8mb4;

-- 1. جدول تخزين بيانات المدرسة الموحدة والقفل التفاؤلي
CREATE TABLE IF NOT EXISTS `sc_store` (
  `id` INT NOT NULL DEFAULT 1,
  `data` LONGTEXT NOT NULL,
  `ver` INT NOT NULL DEFAULT 1,
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. جدول الصفحة العامة والإعدادات المنفصلة
CREATE TABLE IF NOT EXISTS `sc_public` (
  `id` VARCHAR(64) NOT NULL,
  `val` LONGTEXT NOT NULL,
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. حساب المدير العام (المسؤول الرئيسي)
CREATE TABLE IF NOT EXISTS `sc_auth` (
  `id` INT NOT NULL DEFAULT 1,
  `username` VARCHAR(64) NOT NULL,
  `pass_hash` VARCHAR(255) NOT NULL,
  `is_default` INT NOT NULL DEFAULT 0,
  `email` VARCHAR(128) NOT NULL DEFAULT '',
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. حسابات المعلمين والإداريين والصلاحيات
CREATE TABLE IF NOT EXISTS `sc_users` (
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

-- 5. جدول الجلسات والتوكنات الموثوقة (مشفرة sha256)
CREATE TABLE IF NOT EXISTS `sc_tokens` (
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

-- 6. كلمات مرور وحسابات الطلاب
CREATE TABLE IF NOT EXISTS `sc_stu` (
  `id` VARCHAR(64) NOT NULL,
  `pass_hash` VARCHAR(255) NOT NULL,
  `is_default` INT NOT NULL DEFAULT 1,
  `must_change_pass` INT NOT NULL DEFAULT 1,
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. حسابات أولياء الأمور (المفتاح هو آخر 9 أرقام من الهاتف)
CREATE TABLE IF NOT EXISTS `sc_parents` (
  `phone_key` VARCHAR(16) NOT NULL,
  `pass_hash` VARCHAR(255) NOT NULL,
  `is_default` INT NOT NULL DEFAULT 1,
  `must_change_pass` INT NOT NULL DEFAULT 1,
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`phone_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. محاولات تسجيل الدخول لمكافحة القوة الغاشمة (Brute Force)
CREATE TABLE IF NOT EXISTS `sc_tries` (
  `id` INT AUTO_INCREMENT NOT NULL,
  `ip` VARCHAR(45) NOT NULL,
  `username` VARCHAR(64) NOT NULL,
  `attempted_at` DATETIME NOT NULL,
  `success` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_sc_tries_ip` (`ip`, `attempted_at`),
  KEY `idx_sc_tries_user` (`username`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. رموز استعادة كلمة المرور
CREATE TABLE IF NOT EXISTS `sc_resets` (
  `id` INT AUTO_INCREMENT NOT NULL,
  `token_hash` VARCHAR(64) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_sc_resets_hash` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. المراسلات الداخلية بين الإدارة والمعلمين
CREATE TABLE IF NOT EXISTS `sc_pm` (
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

-- 11. سجل التواجد الحي الآن
CREATE TABLE IF NOT EXISTS `sc_presence` (
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

-- 12. سجل العمليات والتدقيق الأمني (Audit Log)
CREATE TABLE IF NOT EXISTS `sc_audit` (
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

-- 13. النسخ الاحتياطية المضغوطة
CREATE TABLE IF NOT EXISTS `sc_snaps` (
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

SET FOREIGN_KEY_CHECKS = 1;
