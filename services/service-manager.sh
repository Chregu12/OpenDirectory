#!/bin/bash
# OpenDirectory Service Manager
# Unified service management script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base directory
SERVICES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Service categories
CATEGORIES=("core" "enterprise" "domains" "api-backend" "integration-service")

# Functions
print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}    OpenDirectory Service Manager${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

list_services() {
    echo -e "${GREEN}📁 Service Structure:${NC}"
    for category in "${CATEGORIES[@]}"; do
        if [ -d "$SERVICES_DIR/$category" ]; then
            echo -e "${YELLOW}  $category/:${NC}"
            if [ "$category" = "enterprise" ]; then
                # Special handling for enterprise subdirectories
                for subdir in "$SERVICES_DIR/$category"/*; do
                    if [ -d "$subdir" ]; then
                        basename_dir=$(basename "$subdir")
                        echo -e "    └── $basename_dir/"
                        count=$(find "$subdir" -name "*.js" 2>/dev/null | wc -l | tr -d ' ')
                        echo -e "        (${count} services)"
                    fi
                done
            else
                # Regular listing for other categories
                for service in "$SERVICES_DIR/$category"/*; do
                    if [ -d "$service" ] || [ -f "$service" ]; then
                        echo -e "    └── $(basename "$service")"
                    fi
                done
            fi
        fi
    done
}

count_services() {
    echo -e "${GREEN}📊 Service Statistics:${NC}"
    
    total=0
    for category in "${CATEGORIES[@]}"; do
        if [ -d "$SERVICES_DIR/$category" ]; then
            if [ "$category" = "enterprise" ]; then
                count=$(find "$SERVICES_DIR/$category" -name "*.js" 2>/dev/null | wc -l | tr -d ' ')
            elif [ "$category" = "core" ] || [ "$category" = "domains" ]; then
                count=$(ls -d "$SERVICES_DIR/$category"/*/ 2>/dev/null | wc -l | tr -d ' ')
            else
                count=1
            fi
            echo -e "  ${YELLOW}$category:${NC} $count services"
            total=$((total + count))
        fi
    done
    echo -e "  ${GREEN}Total:${NC} $total services"
}

start_service() {
    local service=$1
    echo -e "${YELLOW}Starting service: $service${NC}"
    
    # Find service directory
    for category in "${CATEGORIES[@]}"; do
        service_path="$SERVICES_DIR/$category/$service"
        if [ -d "$service_path" ]; then
            if [ -f "$service_path/package.json" ]; then
                cd "$service_path"
                npm start &
                echo -e "${GREEN}✅ Started $service${NC}"
                return 0
            fi
        fi
    done
    
    echo -e "${RED}❌ Service not found: $service${NC}"
    return 1
}

start_all() {
    echo -e "${YELLOW}Starting all services...${NC}"
    
    # Start core services first
    for service in "$SERVICES_DIR/core"/*; do
        if [ -d "$service" ] && [ -f "$service/package.json" ]; then
            service_name=$(basename "$service")
            start_service "$service_name"
        fi
    done
    
    # Start API backend
    if [ -d "$SERVICES_DIR/api-backend" ] && [ -f "$SERVICES_DIR/api-backend/package.json" ]; then
        cd "$SERVICES_DIR/api-backend"
        npm start &
        echo -e "${GREEN}✅ Started api-backend${NC}"
    fi
    
    echo -e "${GREEN}All services started!${NC}"
}

check_health() {
    echo -e "${GREEN}🔍 Checking service health...${NC}"
    
    # Check if services directories exist
    for category in "${CATEGORIES[@]}"; do
        if [ -d "$SERVICES_DIR/$category" ]; then
            echo -e "  ✅ $category directory exists"
        else
            echo -e "  ❌ $category directory missing"
        fi
    done
    
    # Check for package.json files
    echo -e "\n${YELLOW}Checking service configurations:${NC}"
    for service in "$SERVICES_DIR/core"/*; do
        if [ -d "$service" ]; then
            service_name=$(basename "$service")
            if [ -f "$service/package.json" ]; then
                echo -e "  ✅ $service_name configured"
            else
                echo -e "  ⚠️  $service_name missing package.json"
            fi
        fi
    done
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies for all services...${NC}"
    
    for category in "${CATEGORIES[@]}"; do
        if [ "$category" = "enterprise" ]; then
            # Skip enterprise as it has subdirectories with individual services
            continue
        fi
        
        for service in "$SERVICES_DIR/$category"/*; do
            if [ -d "$service" ] && [ -f "$service/package.json" ]; then
                service_name=$(basename "$service")
                echo -e "${BLUE}Installing dependencies for $service_name...${NC}"
                cd "$service"
                npm install
            fi
        done
    done
    
    echo -e "${GREEN}✅ All dependencies installed!${NC}"
}

# Main menu
case "${1:-}" in
    list)
        print_header
        list_services
        ;;
    count)
        print_header
        count_services
        ;;
    start)
        print_header
        if [ -z "${2:-}" ]; then
            start_all
        else
            start_service "$2"
        fi
        ;;
    health)
        print_header
        check_health
        ;;
    install)
        print_header
        install_dependencies
        ;;
    *)
        print_header
        echo "Usage: $0 {list|count|start [service]|health|install}"
        echo ""
        echo "Commands:"
        echo "  list    - List all services by category"
        echo "  count   - Show service statistics"
        echo "  start   - Start all services or specific service"
        echo "  health  - Check service health status"
        echo "  install - Install dependencies for all services"
        echo ""
        echo "Examples:"
        echo "  $0 list"
        echo "  $0 start"
        echo "  $0 start api-backend"
        echo "  $0 health"
        exit 1
        ;;
esac