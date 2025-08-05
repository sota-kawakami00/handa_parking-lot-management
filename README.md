# 駐車場管理システム設計書

## 目次
1. [システム概要](#1-システム概要)
2. [権限設計](#2-権限設計)
3. [データベース設計](#3-データベース設計firestore)
4. [Flutter Web アプリ設計](#4-flutter-web-アプリ設計)
5. [API設計](#5-api設計cloud-functions)
6. [機能詳細設計](#6-機能詳細設計)
7. [セキュリティ設計](#7-セキュリティ設計)
8. [運用・監視](#8-運用監視)
9. [開発・デプロイ](#9-開発デプロイ)
10. [Web固有の考慮事項](#10-web固有の考慮事項)
11. [今後の拡張予定](#11-今後の拡張予定)
12. [運用手順書](#12-運用手順書)

---

## 1. システム概要

### 1.1 目的
駐車場の入退場管理、台数管理、アラート通知機能を持つモバイル・WEBアプリケーションシステム

### 1.2 技術スタック
- **フロントエンド**: Flutter Web
- **バックエンド**: Firebase
    - Authentication（認証）
    - Firestore Database（データベース）
    - Cloud Functions（API・ビジネスロジック）
    - Cloud Messaging（ブラウザ通知）
    - Cloud Storage（ファイル保存・QRコード画像）
    - Hosting（Webアプリデプロイ）

### 1.3 デバイス対応
- **一般ユーザー**: スマートフォン専用（レスポンシブデザイン）
- **幹部以上**: スマートフォン・PC・タブレット対応

---

## 2. 権限設計

### 2.1 権限レベル
1. **一般** (Level 1) - ログイン不要、時間帯別パスワード認証
2. **幹部** (Level 2) - Firebase認証必須
3. **委員会** (Level 3) - Firebase認証必須
4. **パート長** (Level 4) - Firebase認証必須
5. **admin** (Level 5) - Firebase認証必須

### 2.2 機能別権限マトリックス

| 機能 | 一般 | 幹部 | 委員会 | パート長 | admin |
|------|------|------|--------|----------|-------|
| 駐車場の入退場管理 | ○ | ○ | ○ | ○ | ○ |
| アラート通知 | ○ | ○ | ○ | ○ | ○ |
| 台数設定 | × | × | ○ | ○ | ○ |
| 担当者設定 | × | × | × | ○ | ○ |
| 権限設定 | × | × | × | ○ | ○ |
| グラフ表示 | × | × | ○ | ○ | ○ |
| **時間帯パスワード設定** | × | × | × | ○ | ○ |

### 2.3 認証フロー
- **一般ユーザー**: 時間帯別4桁パスワード入力 → 機能利用可能
- **幹部以上**: Firebase認証 → 全権限機能利用可能

---

## 3. データベース設計（Firestore）

### 3.1 コレクション構造

```
parking_system/
├── users/
│   └── {userId}
│       ├── email: string
│       ├── name: string
│       ├── role: string (一般/幹部/委員会/パート長/admin)
│       ├── createdAt: timestamp
│       └── updatedAt: timestamp
│
├── parking_lots/
│   └── {lotId}
│       ├── name: string
│       ├── maxCapacity: number
│       ├── currentCount: number
│       ├── isActive: boolean
│       ├── createdAt: timestamp
│       └── updatedAt: timestamp
│
├── parking_records/
│   └── {recordId}
│       ├── userId: string
│       ├── lotId: string
│       ├── action: string (enter/exit)
│       ├── timestamp: timestamp
│       └── note: string?
│
├── alerts/
│   └── {alertId}
│       ├── type: string (capacity_full/unauthorized_entry/system_error)
│       ├── message: string
│       ├── lotId: string
│       ├── isRead: boolean
│       ├── targetRoles: array<string>
│       ├── createdAt: timestamp
│       └── priority: string (low/medium/high)
│
├── settings/
│   └── {settingId}
│       ├── lotId: string
│       ├── alertThreshold: number
│       ├── operatingHours: object
│       ├── updatedBy: string
│       └── updatedAt: timestamp
│
├── time_passwords/
│   └── {timeSlotId}
│       ├── startTime: string (HH:mm format)
│       ├── endTime: string (HH:mm format)
│       ├── password: string (4桁)
│       ├── qrCodeUrl: string (QRコード画像URL)
│       ├── isActive: boolean
│       ├── validDays: array<string> (monday, tuesday, etc.)
│       ├── createdBy: string
│       ├── createdAt: timestamp
│       └── updatedAt: timestamp
│
└── assignments/
    └── {assignmentId}
        ├── userId: string
        ├── lotId: string
        ├── assignedBy: string
        ├── assignedAt: timestamp
        └── isActive: boolean
```

### 3.2 セキュリティルール例

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // ユーザー認証チェック（Firebase認証）
    function isAuthenticated() {
      return request.auth != null;
    }
    
    // 権限レベルチェック
    function hasRole(role) {
      return isAuthenticated() && 
             get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == role;
    }
    
    // 権限レベル以上チェック
    function hasMinRole(minLevel) {
      let userRole = get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role;
      let roleLevel = userRole == 'admin' ? 5 :
                     userRole == 'パート長' ? 4 :
                     userRole == '委員会' ? 3 :
                     userRole == '幹部' ? 2 : 1;
      return roleLevel >= minLevel;
    }
    
    match /users/{userId} {
      allow read: if isAuthenticated();
      allow write: if hasMinRole(4) || request.auth.uid == userId;
    }
    
    // 一般ユーザーもアクセス可能（時間帯パスワード認証済み前提）
    match /parking_records/{recordId} {
      allow read, write: if true; // Cloud Functionsで認証チェック
    }
    
    match /settings/{settingId} {
      allow read: if hasMinRole(3);
      allow write: if hasMinRole(3);
    }
    
    // 時間帯パスワード設定（パート長以上のみ）
    match /time_passwords/{timeSlotId} {
      allow read: if hasMinRole(4);
      allow write: if hasMinRole(4);
    }
  }
}
```

---

## 4. Flutter Web アプリ設計

### 4.1 アーキテクチャ
- **パターン**: MVVM + Riverpod
- **状態管理**: Riverpod
- **ルーティング**: GoRouter
- **データ層**: Repository Pattern
- **レスポンシブ対応**: BreakPoint対応（Mobile/Tablet/Desktop）

### 4.2 ディレクトリ構造

```
lib/
├── main.dart
├── app.dart
├── core/
│   ├── constants/
│   │   ├── app_constants.dart
│   │   ├── breakpoints.dart
│   │   └── routes.dart
│   ├── errors/
│   ├── services/
│   │   ├── firebase_service.dart
│   │   ├── notification_service.dart
│   │   ├── qr_service.dart
│   │   └── camera_service.dart
│   └── utils/
│       ├── responsive_utils.dart
│       ├── date_utils.dart
│       └── device_utils.dart
├── features/
│   ├── auth/
│   │   ├── data/
│   │   ├── domain/
│   │   └── presentation/
│   │       ├── pages/
│   │       │   ├── general_auth_page.dart (スマホ特化)
│   │       │   └── admin_auth_page.dart (レスポンシブ)
│   │       ├── widgets/
│   │       │   ├── qr_scanner_widget.dart
│   │       │   └── numeric_keypad_widget.dart
│   │       └── providers/
│   ├── parking/
│   │   ├── data/
│   │   ├── domain/
│   │   └── presentation/
│   │       ├── pages/
│   │       │   ├── general_parking_page.dart (スマホ特化)
│   │       │   └── admin_parking_page.dart (レスポンシブ)
│   │       └── widgets/
│   ├── alerts/
│   ├── settings/
│   ├── analytics/
│   └── profile/
├── shared/
│   ├── widgets/
│   │   ├── responsive/
│   │   ├── mobile/
│   │   │   ├── mobile_layout.dart
│   │   │   └── mobile_navigation.dart
│   │   ├── layouts/
│   │   └── common/
│   ├── models/
│   └── providers/
└── l10n/
```

### 4.3 レスポンシブ設計

```dart
// Breakpoints
class AppBreakpoints {
  static const double mobile = 768;
  static const double tablet = 1024;
  static const double desktop = 1440;
}

// デバイス判定
class DeviceUtils {
  static bool isMobile(BuildContext context) {
    return MediaQuery.of(context).size.width < AppBreakpoints.mobile;
  }
  
  static bool isTablet(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    return width >= AppBreakpoints.mobile && width < AppBreakpoints.desktop;
  }
  
  static bool isDesktop(BuildContext context) {
    return MediaQuery.of(context).size.width >= AppBreakpoints.desktop;
  }
  
  // 一般ユーザー用のモバイル最適化チェック
  static bool isOptimalForGeneral(BuildContext context) {
    return isMobile(context);
  }
}

// Responsive Layout Widget（管理者用）
class ResponsiveLayout extends StatelessWidget {
  final Widget mobile;
  final Widget? tablet;
  final Widget desktop;
  
  const ResponsiveLayout({
    Key? key,
    required this.mobile,
    this.tablet,
    required this.desktop,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= AppBreakpoints.desktop) {
          return desktop;
        } else if (constraints.maxWidth >= AppBreakpoints.tablet) {
          return tablet ?? desktop;
        } else {
          return mobile;
        }
      },
    );
  }
}

// 一般ユーザー専用モバイルレイアウト
class MobileOnlyLayout extends StatelessWidget {
  final Widget child;
  final String? desktopMessage;
  
  const MobileOnlyLayout({
    Key? key,
    required this.child,
    this.desktopMessage,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    if (DeviceUtils.isMobile(context)) {
      return child;
    } else {
      return Scaffold(
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.smartphone, size: 64, color: Colors.grey),
              SizedBox(height: 16),
              Text(
                desktopMessage ?? 'この機能はスマートフォンでご利用ください',
                style: Theme.of(context).textTheme.headlineSmall,
                textAlign: TextAlign.center,
              ),
              SizedBox(height: 8),
              Text(
                'QRコードでアクセスするか、スマートフォンでこのページを開いてください',
                style: Theme.of(context).textTheme.bodyMedium,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }
  }
}
```

### 4.4 主要モデルクラス

```dart
// User Model
class User {
  final String id;
  final String email;
  final String name;
  final UserRole role;
  final DateTime createdAt;
  final DateTime updatedAt;
}

enum UserRole {
  general('一般', 1),
  executive('幹部', 2),
  committee('委員会', 3),
  partLeader('パート長', 4),
  admin('admin', 5);
  
  const UserRole(this.displayName, this.level);
  final String displayName;
  final int level;
}

// 時間帯パスワード設定モデル
class TimePassword {
  final String id;
  final TimeOfDay startTime;
  final TimeOfDay endTime;
  final String password; // 4桁
  final String? qrCodeUrl; // QRコード画像URL
  final bool isActive;
  final List<String> validDays; // ['monday', 'tuesday', ...]
  final String createdBy;
  final DateTime createdAt;
  final DateTime updatedAt;
  
  // 現在時刻が有効時間帯かチェック
  bool isValidTime(DateTime now) {
    final currentTime = TimeOfDay.fromDateTime(now);
    final currentDay = _getDayString(now.weekday);
    
    return isActive && 
           validDays.contains(currentDay) &&
           _isTimeInRange(currentTime, startTime, endTime);
  }
  
  String _getDayString(int weekday) {
    switch (weekday) {
      case 1: return 'monday';
      case 2: return 'tuesday';
      case 3: return 'wednesday';
      case 4: return 'thursday';
      case 5: return 'friday';
      case 6: return 'saturday';
      case 7: return 'sunday';
      default: return '';
    }
  }
  
  bool _isTimeInRange(TimeOfDay current, TimeOfDay start, TimeOfDay end) {
    final currentMinutes = current.hour * 60 + current.minute;
    final startMinutes = start.hour * 60 + start.minute;
    final endMinutes = end.hour * 60 + end.minute;
    
    if (startMinutes <= endMinutes) {
      return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } else {
      // 日跨ぎの場合
      return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }
  }
}

// 認証状態管理
class AuthState {
  final bool isAuthenticated;
  final UserRole? userRole;
  final bool isGeneralAccess; // 一般ユーザーの時間帯パスワード認証済み
  final DateTime? generalAuthExpiry;
  
  const AuthState({
    required this.isAuthenticated,
    this.userRole,
    this.isGeneralAccess = false,
    this.generalAuthExpiry,
  });
  
  bool get canAccessParkingFeatures {
    return isAuthenticated || 
           (isGeneralAccess && 
            generalAuthExpiry != null && 
            DateTime.now().isBefore(generalAuthExpiry!));
  }
}

// Parking Record Model
class ParkingRecord {
  final String id;
  final String? userId; // 一般ユーザーの場合はnull
  final String lotId;
  final ParkingAction action;
  final DateTime timestamp;
  final String? note;
  final bool isGeneralUser; // 一般ユーザーによる操作かどうか
}

enum ParkingAction { enter, exit }

// Alert Model
class Alert {
  final String id;
  final AlertType type;
  final String message;
  final String lotId;
  final bool isRead;
  final List<UserRole> targetRoles;
  final DateTime createdAt;
  final AlertPriority priority;
}
```

### 4.5 Web固有の実装

```dart
// QRコード関連サービス
class QRService {
  // QRコードスキャン（カメラ使用）
  static Future<String?> scanQRCode() async {
    if (kIsWeb) {
      try {
        // html5_qrcode パッケージまたはカメラAPI使用
        final result = await _scanWithCamera();
        return result;
      } catch (e) {
        print('QRスキャンエラー: $e');
        return null;
      }
    }
    return null;
  }
  
  // QRコード生成（管理者用）
  static Future<String> generateQRCode(String password) async {
    // QRコード画像生成してCloud Storageに保存
    final qrData = json.encode({
      'type': 'parking_password',
      'password': password,
      'timestamp': DateTime.now().toIso8601String(),
    });
    
    // QRコード画像生成処理
    return await _uploadQRCodeImage(qrData);
  }
  
  static Future<String?> _scanWithCamera() async {
    // WebRTC APIを使用したカメラアクセス
    // 実装詳細は省略
    return null;
  }
  
  static Future<String> _uploadQRCodeImage(String data) async {
    // Cloud Storage への画像アップロード
    // 実装詳細は省略
    return '';
  }
}

// スマホ特化のUI コンポーネント
class MobileNumericKeypad extends StatelessWidget {
  final Function(String) onNumberPressed;
  final VoidCallback onBackspace;
  final VoidCallback onClear;
  
  const MobileNumericKeypad({
    Key? key,
    required this.onNumberPressed,
    required this.onBackspace,
    required this.onClear,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.all(16),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 数字キーパッド（3x4レイアウト）
          for (int row = 0; row < 4; row++)
            Row(
              children: [
                for (int col = 0; col < 3; col++)
                  Expanded(
                    child: _buildKeypadButton(context, row, col),
                  ),
              ],
            ),
        ],
      ),
    );
  }
  
  Widget _buildKeypadButton(BuildContext context, int row, int col) {
    String text = '';
    VoidCallback? onPressed;
    
    if (row < 3) {
      // 数字ボタン (1-9)
      final number = row * 3 + col + 1;
      text = number.toString();
      onPressed = () => onNumberPressed(text);
    } else {
      // 最下段の特別ボタン
      if (col == 0) {
        text = 'クリア';
        onPressed = onClear;
      } else if (col == 1) {
        text = '0';
        onPressed = () => onNumberPressed('0');
      } else {
        text = '削除';
        onPressed = onBackspace;
      }
    }
    
    return Container(
      margin: EdgeInsets.all(4),
      height: 60,
      child: ElevatedButton(
        onPressed: onPressed,
        style: ElevatedButton.styleFrom(
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
        ),
        child: Text(
          text,
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
        ),
      ),
    );
  }
}

// QRスキャナーウィジェット
class QRScannerWidget extends StatefulWidget {
  final Function(String) onQRScanned;
  
  const QRScannerWidget({Key? key, required this.onQRScanned}) : super(key: key);
  
  @override
  _QRScannerWidgetState createState() => _QRScannerWidgetState();
}

class _QRScannerWidgetState extends State<QRScannerWidget> {
  bool _isScanning = false;
  
  @override
  Widget build(BuildContext context) {
    return Container(
      height: 200,
      decoration: BoxDecoration(
        border: Border.all(color: Colors.grey),
        borderRadius: BorderRadius.circular(8),
      ),
      child: _isScanning
          ? Center(child: CircularProgressIndicator())
          : Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.qr_code_scanner, size: 48, color: Colors.blue),
                SizedBox(height: 16),
                ElevatedButton(
                  onPressed: _startScanning,
                  child: Text('QRコードをスキャン'),
                ),
              ],
            ),
    );
  }
  
  Future<void> _startScanning() async {
    setState(() => _isScanning = true);
    
    try {
      final result = await QRService.scanQRCode();
      if (result != null) {
        // QRコードからパスワード抽出
        final data = json.decode(result);
        if (data['type'] == 'parking_password') {
          widget.onQRScanned(data['password']);
        }
      }
    } catch (e) {
      // エラーハンドリング
    } finally {
      setState(() => _isScanning = false);
    }
  }
}

// 時間帯パスワード認証サービス
class TimePasswordAuthService {
  static const String _authKey = 'general_auth_token';
  static const String _expiryKey = 'general_auth_expiry';
  
  // 時間帯パスワード認証
  static Future<bool> authenticateWithTimePassword(String password) async {
    try {
      final response = await http.post(
        Uri.parse('${Constants.apiBaseUrl}/auth/time-password'),
        body: {'password': password, 'timestamp': DateTime.now().toIso8601String()},
      );
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success']) {
          // 認証トークンを保存（30分有効）
          final expiry = DateTime.now().add(Duration(minutes: 30));
          WebStorageService.setItem(_authKey, data['token']);
          WebStorageService.setItem(_expiryKey, expiry.toIso8601String());
          return true;
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }
  
  // 認証状態チェック
  static bool isGeneralUserAuthenticated() {
    final token = WebStorageService.getItem(_authKey);
    final expiryStr = WebStorageService.getItem(_expiryKey);
    
    if (token == null || expiryStr == null) return false;
    
    final expiry = DateTime.parse(expiryStr);
    if (DateTime.now().isAfter(expiry)) {
      clearAuthentication();
      return false;
    }
    
    return true;
  }
  
  // 認証情報クリア
  static void clearAuthentication() {
    WebStorageService.removeItem(_authKey);
    WebStorageService.removeItem(_expiryKey);
  }
}

// ローカルストレージ
class WebStorageService {
  static void setItem(String key, String value) {
    if (kIsWeb) {
      html.window.localStorage[key] = value;
    }
  }
  
  static String? getItem(String key) {
    if (kIsWeb) {
      return html.window.localStorage[key];
    }
    return null;
  }
  
  static void removeItem(String key) {
    if (kIsWeb) {
      html.window.localStorage.remove(key);
    }
  }
}
```

---

## 5. API設計（Cloud Functions）

### 5.1 エンドポイント一覧

```
POST /api/auth/time-password          # 時間帯パスワード認証
GET  /api/time-passwords              # 時間帯パスワード一覧取得
POST /api/time-passwords              # 時間帯パスワード作成
PUT  /api/time-passwords/{id}         # 時間帯パスワード更新
DELETE /api/time-passwords/{id}       # 時間帯パスワード削除
POST /api/parking/enter               # 入場記録
POST /api/parking/exit                # 退場記録
GET  /api/parking/status/{lotId}      # 駐車場状況取得
GET  /api/parking/history             # 履歴取得（認証済みユーザーのみ）
POST /api/alerts/create               # アラート作成
GET  /api/alerts/list                 # アラート一覧
PUT  /api/alerts/{alertId}/read       # アラート既読
GET  /api/analytics/summary           # 分析サマリー（委員会以上）
GET  /api/analytics/chart-data        # グラフデータ（委員会以上）
POST /api/settings/update             # 設定更新
GET  /api/users/list                  # ユーザー一覧
PUT  /api/users/{userId}/role         # ユーザー権限変更
```

### 5.2 API レスポンス例

```json
// POST /api/auth/time-password
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresAt": "2024-01-15T11:00:00Z",
    "timeSlot": {
      "startTime": "09:00",
      "endTime": "17:00"
    }
  }
}

// GET /api/time-passwords (パート長以上のみ)
{
  "success": true,
  "data": [
    {
      "id": "time_001",
      "startTime": "09:00",
      "endTime": "17:00",
      "password": "1234",
      "qrCodeUrl": "https://storage.googleapis.com/parking-system/qr-codes/time_001.png",
      "isActive": true,
      "validDays": ["monday", "tuesday", "wednesday", "thursday", "friday"],
      "createdBy": "user_123",
      "createdAt": "2024-01-01T00:00:00Z"
    }
  ]
}

// GET /api/parking/status/{lotId}
{
  "success": true,
  "data": {
    "lotId": "lot_001",
    "name": "第1駐車場",
    "currentCount": 25,
    "maxCapacity": 50,
    "availableSpaces": 25,
    "utilizationRate": 0.5,
    "lastUpdated": "2024-01-15T10:30:00Z"
  }
}

// POST /api/parking/enter (一般ユーザー対応)
{
  "success": true,
  "data": {
    "recordId": "record_001",
    "action": "enter",
    "timestamp": "2024-01-15T10:30:00Z",
    "isGeneralUser": true,
    "currentCount": 26
  }
}

// GET /api/analytics/chart-data
{
  "success": true,
  "data": {
    "daily": [
      {
        "date": "2024-01-15",
        "entries": 45,
        "exits": 42,
        "peakOccupancy": 38,
        "generalUserEntries": 12,
        "registeredUserEntries": 33
      }
    ],
    "hourly": [
      {
        "hour": 9,
        "avgOccupancy": 15.5
      }
    ]
  }
}
```

---

## 6. 機能詳細設計

### 6.1 駐車場の入退場管理

#### **一般ユーザー用（スマホ専用）**
- 大きなタッチボタンによる直感的操作
- 4桁パスワード入力方法選択
    - 数字キーパッド入力
    - QRコードスキャン入力
- ワンタップ入退場ボタン（指が太くても操作しやすい）
- 満車時の大きなアラート表示
- バイブレーション対応（操作フィードバック）

#### **登録ユーザー用（スマホ・PC対応）**
- Firebase認証ログイン
- レスポンシブデザイン対応
- 入退場ボタン操作
- 履歴参照機能
- リアルタイム台数更新

### 6.2 時間帯パスワード管理（パート長以上）

#### **パスワード設定機能**
- 開始時刻・終了時刻設定
- 4桁パスワード生成・変更
- QRコード自動生成・表示・印刷対応
- 有効曜日選択（月〜日）
- アクティブ/非アクティブ切り替え
- 複数時間帯設定対応

#### **QRコード管理**
- パスワード変更時の自動QRコード更新
- 高解像度QRコード画像出力
- QRコードの印刷用PDF生成
- 掲示用QRコードラベル作成

#### **管理画面**
- 時間帯一覧表示（PC: テーブル表示、スマホ: カード表示）
- パスワード使用状況統計
- 一般ユーザーアクセスログ
- QRコードダウンロード機能

### 6.3 アラート通知

#### **通知タイプ**
- 満車警告
- 不正入場検知
- システムエラー
- 定期メンテナンス
- 時間帯パスワード認証失敗通知
- QRコード読み取りエラー

#### **配信方法**
- **スマホ**: バイブレーション + 画面通知
- **PC**: ブラウザ通知API
- メール通知（重要なアラート）
- 権限別配信

### 6.4 台数設定（委員会以上）
- 最大収容台数設定
- 警告閾値設定
- 営業時間設定
- **レスポンシブ対応**: PC（詳細設定画面）、スマホ（簡素化画面）

### 6.5 担当者設定（パート長以上）
- ユーザーと駐車場の紐付け
- 責任者指定
- シフト管理
- **デバイス最適化**: PC（複数選択・一括操作）、スマホ（個別操作）

### 6.6 権限設定（パート長以上）
- ユーザー権限変更
- 機能アクセス制御
- 監査ログ
- **操作性**: PC（詳細権限設定）、スマホ（基本権限のみ）

### 6.7 グラフ表示（委員会以上）
- 利用状況の時系列グラフ
- 稼働率分析
- 一般ユーザー vs 登録ユーザー利用統計
- 時間帯別利用パターン分析
- QRコード vs 手動入力の利用比率
- 予測データ表示
- **表示最適化**:
    - PC: 複数グラフ同時表示、詳細データ表示
    - スマホ: 1グラフずつ表示、スワイプ切り替え

---

## 7. セキュリティ設計

### 7.1 認証・認可
- **登録ユーザー**: Firebase Authentication使用
- **一般ユーザー**: 時間帯別4桁パスワード認証
    - パスワード総当たり攻撃対策（5回失敗で30分ロック）
    - セッション管理（30分自動タイムアウト）
    - 時間帯外アクセス制限
    - IPアドレス制限（オプション）
    - **QRコードセキュリティ**:
        - QRコード内データ暗号化
        - タイムスタンプによる有効期限チェック
        - ワンタイム要素の組み込み

### 7.2 データ保護
- Firestore Security Rules
- データ暗号化
- アクセスログ記録
- 一般ユーザーのプライバシー保護（個人情報不要）
- QRコード画像の安全な保存・配信

### 7.3 API セキュリティ
- HTTPS通信強制
- レート制限（一般ユーザー: 1分間に10回、登録ユーザー: 1分間に30回）
- 入力値検証
- 時間帯パスワード・QRコードのハッシュ化保存
- JWTトークンによるセッション管理
- **スマホ特有セキュリティ**:
    - カメラアクセス権限管理
    - 悪意のあるQRコード検出

### 7.4 監査・ログ
- 一般ユーザーアクセスログ
- パスワード認証失敗ログ
- QRコード読み取りログ
- 権限変更履歴
- データ変更追跡
- デバイス種別・ブラウザ情報記録

---

## 8. 運用・監視

### 8.1 ログ管理
- アクセスログ
- エラーログ
- 操作履歴
- 時間帯パスワード使用履歴
- QRコード利用統計
- デバイス別利用統計

### 8.2 パフォーマンス監視
- Firebase Performance Monitoring
- クラッシュレポート
- ユーザー行動分析
- 一般ユーザー利用統計
- **スマホ特有監視**:
    - カメラ機能利用率
    - QRスキャン成功率
    - レスポンス時間（モバイル回線考慮）

### 8.3 バックアップ・復旧
- Firestore自動バックアップ
- 災害復旧計画
- データ移行手順
- 時間帯パスワード設定バックアップ
- QRコード画像バックアップ

---

## 9. 開発・デプロイ

### 9.1 開発環境
- Flutter SDK 3.16+ (Web対応)
- Firebase CLI
- VS Code / IntelliJ IDEA
- Chrome DevTools（デバッグ用）
- **スマホテスト環境**:
    - Android Chrome
    - iOS Safari
    - 実機テスト用デバイス

### 9.2 CI/CD
- GitHub Actions
- 自動テスト実行
- Firebase Hosting自動デプロイ
- ステージング環境での検証
- **デバイス別テスト**:
    - PC ブラウザテスト
    - スマホ実機テスト
    - レスポンシブテスト

### 9.3 品質管理
- 単体テスト
- 統合テスト
- E2Eテスト（Selenium/Playwright）
- ブラウザ互換性テスト
- セキュリティテスト（時間帯パスワード認証、QRコード）
- **スマホ特有テスト**:
    - タッチ操作テスト
    - カメラ機能テスト
    - パフォーマンステスト（低速回線）
- コードレビュー

### 9.4 デプロイ設定

```yaml
# firebase.json
{
  "hosting": {
    "public": "build/web",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "rewrites": [
      {
        "source": "**",
        "destination": "/index.html"
      }
    ],
    "headers": [
      {
        "source": "**/*.@(js|css)",
        "headers": [
          {
            "key": "Cache-Control",
            "value": "max-age=31536000"
          }
        ]
      },
      {
        "source": "/qr-codes/**",
        "headers": [
          {
            "key": "Cache-Control",
            "value": "max-age=86400"
          }
        ]
      }
    ]
  },
  "functions": {
    "source": "functions",
    "runtime": "nodejs18"
  },
  "storage": {
    "rules": "storage.rules"
  }
}
```

### 9.5 Web最適化
- Tree Shaking
- Code Splitting
- 画像最適化（QRコード画像含む）
- PWA対応（オプション）
- SEO対応
- **スマホ最適化**:
    - 軽量化（低速回線対応）
    - タッチ操作最適化
    - バッテリー消費最小化

---

## 10. Web固有の考慮事項

### 10.1 ブラウザ対応

#### **PC対応ブラウザ（管理者用）**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

#### **スマホ対応ブラウザ（一般ユーザー用）**
- Android Chrome 90+
- iOS Safari 14+
- Samsung Internet 15+

### 10.2 パフォーマンス最適化

#### **初期読み込み時間短縮**
- Code Splitting（一般ユーザー用は最小限）
- Lazy Loading
- 画像最適化（QRコード）

#### **リアルタイム通信**
- WebSocket接続の管理
- 接続断時の自動再接続
- オフライン時のデータキャッシュ
- **スマホ配慮**: バックグラウンド時の接続管理

### 10.3 セキュリティ（Web特有）

#### **HTTPS強制**
- HTTP Strict Transport Security (HSTS)
- Mixed Content対策

#### **XSS/CSRF対策**
- Content Security Policy (CSP)
- SameSite Cookie属性
- CSRF Token

#### **カメラアクセス制御**
- 適切な権限要求
- プライバシー保護

### 10.4 ユーザビリティ

#### **一般ユーザー向け（スマホ最適化）**
- 大きなタッチターゲット（最小44px）
- 指に優しいボタン配置
- ハイコントラスト表示
- QRコードスキャン時の明確なガイド表示
- 操作完了時のバイブレーションフィードバック
- エラー時の分かりやすいメッセージ

#### **管理者向け（PC・スマホ対応）**
- キーボードショートカット（PC）
    - 入退場操作：Ctrl+E / Ctrl+X
    - 検索：Ctrl+F
    - 設定画面：Ctrl+,
- レスポンシブナビゲーション

#### **アクセシビリティ**
- WAI-ARIA対応
- キーボードナビゲーション
- スクリーンリーダー対応
- カラーコントラスト基準準拠

### 10.5 スマホ特有機能

#### **カメラ統合**
- WebRTC API使用
- QRコード自動検出
- フラッシュライト制御
- ピンチズーム対応

#### **バイブレーション**
- 操作成功時の短いバイブ
- エラー時の警告バイブ
- Navigator.vibrate() API使用

#### **タッチジェスチャー**
- スワイプナビゲーション
- ピンチズーム（グラフ表示）
- ロングタップメニュー

---

## 11. 今後の拡張予定

### 11.1 機能拡張
- 予約システム
- 料金計算機能
- 外部システム連携API
- PWA対応（オフライン機能）
- 時間帯パスワードの自動生成・ローテーション
- **スマホアプリ化**（ネイティブアプリ版）
- 生体認証対応（指紋・Face ID）
- NFC対応

### 11.2 技術的改善
- パフォーマンス最適化
- マルチテナント対応
- 多言語対応
- ダークモード対応
- **AR機能**: QRコード位置案内
- **音声操作**: 声による入退場操作

---

## 12. 運用手順書

### 12.1 時間帯パスワード・QRコード管理運用

#### **1. 定期的なパスワード・QRコード更新**
- 月1回の定期変更推奨
- セキュリティインシデント時の緊急変更
- QRコード掲示物の交換手順

#### **2. QRコード掲示管理**
- 適切な掲示場所の選定
- 汚損・劣化チェック
- 照明・視認性確保

#### **3. 時間帯設定の変更**
- 営業時間変更に伴う設定更新
- 休日・特別営業日の設定調整

#### **4. 利用状況監視**
- 異常なアクセスパターンの検知
- 一般ユーザー利用統計の定期レビュー
- QRコード vs 手動入力の比率分析

### 12.2 トラブルシューティング
- パスワード認証失敗が多発する場合の対処
- QRコード読み取りエラー対応
- カメラアクセス拒否時の代替手順案内
- システム障害時の代替運用手順
- データ不整合発生時の復旧手順

### 12.3 スマホ操作サポート
- QRコードスキャン操作ガイド
- カメラ権限設定方法
- よくある操作エラーと対処法
- 高齢者向け操作サポート資料

---

## 付録

### A. 想定利用フロー

#### **一般ユーザー（スマホ）**
1. スマートフォンでWebサイトにアクセス
2. QRコードスキャンまたは4桁パスワード入力
3. 認証成功後、入場または退場ボタンをタップ
4. バイブレーションで操作完了を確認

#### **管理者（PC・スマホ）**
1. Firebase認証でログイン
2. 権限に応じた管理画面にアクセス
3. 各種設定・監視・分析機能を利用
4. 必要に応じてQRコード生成・更新

### B. セキュリティ仕様詳細

#### **時間帯パスワード暗号化**
- ハッシュ化: bcrypt (コスト12)
- ソルト: ランダム生成
- 保存形式: ハッシュ値のみDB格納

#### **QRコード仕様**
- フォーマット: JSON形式
- 暗号化: AES-256-GCM
- 有効期限: 生成から24時間
- エラー訂正レベル: M (15%)

### C. パフォーマンス要件

#### **レスポンス時間**
- 一般ユーザー認証: 2秒以内
- 入退場操作: 1秒以内
- QRスキャン: 3秒以内
- グラフ表示: 5秒以内

#### **同時接続数**
- 想定最大: 100ユーザー
- 一般ユーザー: 80%
- 管理者: 20%

---

**文書作成日**: 2024年1月15日  
**バージョン**: 1.0  
**作成者**: システム設計チーム