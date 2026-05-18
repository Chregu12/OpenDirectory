#!/usr/bin/env python3
"""Replace all @heroicons/react imports with lucide-react equivalents."""

import re
import os
import glob

# Full mapping: HeroiconName → LucideName
ICON_MAP = {
    # Layout / Navigation
    'HomeIcon':                    'Home',
    'Bars3Icon':                   'Menu',
    'XMarkIcon':                   'X',
    'ChevronLeftIcon':             'ChevronLeft',
    'ChevronRightIcon':            'ChevronRight',
    'ChevronDownIcon':             'ChevronDown',
    'ChevronUpIcon':               'ChevronUp',
    'EllipsisHorizontalIcon':      'MoreHorizontal',
    'EllipsisVerticalIcon':        'MoreVertical',
    'Squares2X2Icon':              'LayoutGrid',
    'RectangleGroupIcon':          'LayoutGrid',
    'RectangleStackIcon':          'Layers',
    'Square2StackIcon':            'Layers2',
    'TableCellsIcon':              'Table2',
    'ListBulletIcon':              'List',
    'ViewColumnsIcon':             'Columns2',
    'AdjustmentsHorizontalIcon':   'SlidersHorizontal',
    'AdjustmentsVerticalIcon':     'SlidersVertical',

    # Search / Magnify
    'MagnifyingGlassIcon':         'Search',
    'MagnifyingGlassCircleIcon':   'ScanSearch',
    'MagnifyingGlassPlusIcon':     'ZoomIn',
    'MagnifyingGlassMinusIcon':    'ZoomOut',
    'FunnelIcon':                  'Filter',

    # Users / People
    'UserIcon':                    'User',
    'UserCircleIcon':              'UserCircle2',
    'UserGroupIcon':               'Users',
    'UsersIcon':                   'Users',
    'UserPlusIcon':                'UserPlus',
    'UserMinusIcon':               'UserMinus',
    'IdentificationIcon':          'CreditCard',
    'FingerPrintIcon':             'Fingerprint',

    # Devices / Hardware
    'ComputerDesktopIcon':         'Monitor',
    'DevicePhoneMobileIcon':       'Smartphone',
    'DeviceTabletIcon':            'Tablet',
    'TvIcon':                      'Tv',
    'PrinterIcon':                 'Printer',
    'CpuChipIcon':                 'Cpu',
    'ServerIcon':                  'Server',
    'ServerStackIcon':             'ServerStack',
    'CircleStackIcon':             'Database',
    'CameraIcon':                  'Camera',
    'VideoCameraIcon':             'Video',
    'MicrophoneIcon':              'Mic',
    'SpeakerWaveIcon':             'Volume2',
    'WifiIcon':                    'Wifi',
    'SignalIcon':                  'Signal',

    # Security
    'ShieldCheckIcon':             'ShieldCheck',
    'ShieldExclamationIcon':       'ShieldAlert',
    'LockClosedIcon':              'Lock',
    'LockOpenIcon':                'Unlock',
    'KeyIcon':                     'Key',
    'BugAntIcon':                  'Bug',
    'NoSymbolIcon':                'Ban',
    'ExclamationTriangleIcon':     'AlertTriangle',
    'ExclamationCircleIcon':       'AlertCircle',
    'InformationCircleIcon':       'Info',

    # Status / Feedback
    'CheckCircleIcon':             'CheckCircle2',
    'XCircleIcon':                 'XCircle',
    'CheckIcon':                   'Check',
    'XMarkIcon':                   'X',
    'MinusIcon':                   'Minus',
    'PlusIcon':                    'Plus',
    'PlusCircleIcon':              'PlusCircle',
    'MinusCircleIcon':             'MinusCircle',
    'SparklesIcon':                'Sparkles',
    'BoltIcon':                    'Zap',
    'FireIcon':                    'Flame',
    'StarIcon':                    'Star',

    # Files / Documents
    'DocumentTextIcon':            'FileText',
    'DocumentIcon':                'File',
    'DocumentDuplicateIcon':       'Copy',
    'DocumentArrowDownIcon':       'FileDown',
    'DocumentArrowUpIcon':         'FileUp',
    'ClipboardIcon':               'Clipboard',
    'ClipboardDocumentListIcon':   'ClipboardList',
    'ClipboardDocumentCheckIcon':  'ClipboardCheck',
    'FolderIcon':                  'Folder',
    'FolderOpenIcon':              'FolderOpen',
    'ArchiveBoxIcon':              'Archive',
    'ArchiveBoxArrowDownIcon':     'ArchiveRestore',
    'InboxIcon':                   'Inbox',
    'TagIcon':                     'Tag',

    # Actions
    'ArrowPathIcon':               'RefreshCw',
    'ArrowLeftIcon':               'ArrowLeft',
    'ArrowRightIcon':              'ArrowRight',
    'ArrowUpIcon':                 'ArrowUp',
    'ArrowDownIcon':               'ArrowDown',
    'ArrowTopRightOnSquareIcon':   'ExternalLink',
    'ArrowDownTrayIcon':           'Download',
    'ArrowUpTrayIcon':             'Upload',
    'ArrowDownOnSquareStackIcon':  'FolderDown',
    'ArrowsUpDownIcon':            'ArrowUpDown',
    'ArrowsRightLeftIcon':         'ArrowLeftRight',
    'ArrowUturnLeftIcon':          'Undo2',
    'ArrowUturnRightIcon':         'Redo2',
    'TrashIcon':                   'Trash2',
    'PencilIcon':                  'Pencil',
    'PencilSquareIcon':            'PenSquare',
    'PaintBrushIcon':              'Paintbrush',
    'EyeIcon':                     'Eye',
    'EyeSlashIcon':                'EyeOff',
    'PlayIcon':                    'Play',
    'PauseIcon':                   'Pause',
    'StopIcon':                    'Square',
    'ForwardIcon':                 'SkipForward',
    'BackwardIcon':                'SkipBack',
    'ShareIcon':                   'Share2',
    'LinkIcon':                    'Link',
    'PaperClipIcon':               'Paperclip',
    'PaperAirplaneIcon':           'Send',

    # Communication
    'BellIcon':                    'Bell',
    'BellAlertIcon':               'BellRing',
    'BellSlashIcon':               'BellOff',
    'EnvelopeIcon':                'Mail',
    'EnvelopeOpenIcon':            'MailOpen',
    'ChatBubbleLeftIcon':          'MessageSquare',
    'ChatBubbleLeftRightIcon':     'MessageSquare',
    'ChatBubbleOvalLeftIcon':      'MessageCircle',
    'PhoneIcon':                   'Phone',

    # Charts / Data
    'ChartBarIcon':                'BarChart2',
    'ChartPieIcon':                'PieChart',
    'PresentationChartLineIcon':   'TrendingUp',
    'PresentationChartBarIcon':    'BarChart',

    # Settings / Config
    'Cog6ToothIcon':               'Settings',
    'Cog8ToothIcon':               'Settings2',
    'WrenchIcon':                  'Wrench',
    'WrenchScrewdriverIcon':       'Wrench',
    'ToolboxIcon':                 'Toolbox',

    # Network / Cloud / Infrastructure
    'GlobeAltIcon':                'Globe',
    'GlobeAmericasIcon':           'Globe2',
    'CloudIcon':                   'Cloud',
    'CloudArrowUpIcon':            'CloudUpload',
    'CloudArrowDownIcon':          'CloudDownload',
    'MapPinIcon':                  'MapPin',
    'SignalSlashIcon':             'SignalZero',

    # Business / Office
    'BuildingOfficeIcon':          'Building2',
    'BuildingLibraryIcon':         'Library',
    'BriefcaseIcon':               'Briefcase',
    'ShoppingBagIcon':             'ShoppingBag',
    'ShoppingCartIcon':            'ShoppingCart',
    'CurrencyDollarIcon':          'DollarSign',
    'CalendarIcon':                'Calendar',
    'CalendarDaysIcon':            'CalendarDays',
    'ClockIcon':                   'Clock',
    'MapIcon':                     'Map',

    # Code / Dev
    'CommandLineIcon':             'Terminal',
    'CodeBracketIcon':             'Code2',
    'CodeBracketSquareIcon':       'FileCode2',
    'CubeIcon':                    'Package',
    'CubeTransparentIcon':         'PackageOpen',
    'PuzzlePieceIcon':             'Puzzle',
    'QrCodeIcon':                  'QrCode',
    'RocketLaunchIcon':            'Rocket',

    # Media
    'PhotoIcon':                   'Image',
    'FilmIcon':                    'Film',
    'MusicalNoteIcon':             'Music',
    'SunIcon':                     'Sun',
    'MoonIcon':                    'Moon',
    'LightBulbIcon':               'Lightbulb',
    'HeartIcon':                   'Heart',
    'BookOpenIcon':                'BookOpen',
    'BookmarkIcon':                'Bookmark',
    'FlagIcon':                    'Flag',
    'GiftIcon':                    'Gift',
    'TrophyIcon':                  'Trophy',

    # Solid variants (just use regular lucide)
    'CheckCircleSolid':            'CheckCircle2',
    'StarIconSolid':               'Star',
    'HeartIconSolid':              'Heart',
    'BookmarkIconSolid':           'Bookmark',
}

def get_used_icons(content):
    """Extract all heroicon names used in this file."""
    used = set()
    # Match import statements
    import_re = re.compile(r'import\s*\{([^}]+)\}\s*from\s*[\'"]@heroicons/react/24/(?:outline|solid)[\'"]')
    for match in import_re.finditer(content):
        items = match.group(1)
        for item in items.split(','):
            item = item.strip()
            # Handle aliases: "CheckCircleIcon as CheckCircleSolid"
            if ' as ' in item:
                orig, alias = [p.strip() for p in item.split(' as ')]
                used.add((orig, alias))
            else:
                if item:
                    used.add((item, None))
    return used

def migrate_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    if '@heroicons/react' not in content:
        return False

    original = content

    # Step 1: Gather all used icons and their aliases
    import_re = re.compile(r'import\s*\{([^}]+)\}\s*from\s*[\'"]@heroicons/react/24/(?:outline|solid)[\'"]')

    lucide_imports_needed = {}  # lucide_name -> local_name (the alias in this file)

    for match in import_re.finditer(content):
        items = match.group(1)
        for item in items.split(','):
            item = item.strip()
            if not item:
                continue
            if ' as ' in item:
                orig, alias = [p.strip() for p in item.split(' as ')]
                lucide_name = ICON_MAP.get(orig, orig)
                # alias stays the same, but we map to lucide
                lucide_imports_needed[lucide_name] = alias
                # In JSX/code, the alias is already the name used, so no rename needed
            else:
                lucide_name = ICON_MAP.get(item, item)
                old_name = item
                # We'll rename old_name → lucide_name in JSX too
                lucide_imports_needed[lucide_name] = lucide_name

    # Step 2: Remove all heroicons imports
    content = re.sub(
        r'import\s*\{[^}]+\}\s*from\s*[\'"]@heroicons/react/24/(?:outline|solid)[\'"];\n?',
        '',
        content
    )

    # Step 3: Rename icon usages in JSX and object literals
    # Only rename icons that have DIFFERENT lucide names (not aliases)
    for match in import_re.finditer(original):
        items = match.group(1)
        for item in items.split(','):
            item = item.strip()
            if not item or ' as ' in item:
                continue
            lucide_name = ICON_MAP.get(item, item)
            if lucide_name != item:
                # Replace as JSX component: <HomeIcon → <Home, </HomeIcon → </Home
                content = re.sub(r'<' + re.escape(item) + r'(\s|/>)', r'<' + lucide_name + r'\1', content)
                content = re.sub(r'</' + re.escape(item) + r'>', r'</' + lucide_name + r'>', content)
                # Replace as value/reference: icon: HomeIcon, icon={HomeIcon}, HomeIcon,
                content = re.sub(r'\b' + re.escape(item) + r'\b', lucide_name, content)

    # Step 4: Build combined lucide import
    if lucide_imports_needed:
        # Sort and deduplicate
        imports_set = set()
        for lucide_name, local_name in lucide_imports_needed.items():
            if lucide_name == local_name:
                imports_set.add(lucide_name)
            else:
                imports_set.add(f'{lucide_name} as {local_name}')

        # Also check for any remaining icon names from the old file
        # that might have been renamed directly
        import_line = "import { " + ", ".join(sorted(imports_set)) + " } from 'lucide-react';\n"

        # Insert after the last 'use client' or before the first import, or at top
        if "from 'lucide-react'" in content:
            # Merge with existing lucide import
            existing_re = re.compile(r"import\s*\{([^}]+)\}\s*from\s*'lucide-react';")
            existing_match = existing_re.search(content)
            if existing_match:
                existing_icons = {i.strip() for i in existing_match.group(1).split(',') if i.strip()}
                for imp in imports_set:
                    existing_icons.add(imp)
                merged = "import { " + ", ".join(sorted(existing_icons)) + " } from 'lucide-react';"
                content = existing_re.sub(merged, content, count=1)
        else:
            # Find insertion point: after 'use client'; or after last existing import
            insert_after = re.search(r"^'use client';\n", content, re.MULTILINE)
            if insert_after:
                pos = insert_after.end()
                content = content[:pos] + import_line + content[pos:]
            else:
                # Insert before first import
                first_import = re.search(r'^import ', content, re.MULTILINE)
                if first_import:
                    content = content[:first_import.start()] + import_line + content[first_import.start():]
                else:
                    content = import_line + content

    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    base = '/home/user/OpenDirectory/frontend/web-app/src'
    files = glob.glob(f'{base}/**/*.tsx', recursive=True) + glob.glob(f'{base}/**/*.ts', recursive=True)

    changed = []
    for f in sorted(files):
        if migrate_file(f):
            changed.append(f.replace(base + '/', ''))
            print(f'  ✓ {f.replace(base + "/", "")}')

    print(f'\n{len(changed)} files migrated.')

if __name__ == '__main__':
    main()
