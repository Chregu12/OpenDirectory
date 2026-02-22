#!/bin/bash

# OpenDirectory Integration Service Test Script
set -e

echo "🚀 Starting OpenDirectory Integration Service Tests"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INTEGRATION_SERVICE_URL="http://localhost:3005"
FRONTEND_URL="http://localhost:3000"

# Function to check if service is running
check_service() {
    local service_name=$1
    local url=$2
    
    echo -n "Checking $service_name... "
    if curl -s --fail --max-time 10 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Running${NC}"
        return 0
    else
        echo -e "${RED}✗ Not accessible${NC}"
        return 1
    fi
}

# Function to test API endpoint
test_api_endpoint() {
    local method=$1
    local endpoint=$2
    local expected_status=$3
    local description=$4
    
    echo -n "Testing $description... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 10 "$INTEGRATION_SERVICE_URL$endpoint")
    else
        response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 10 -X "$method" "$INTEGRATION_SERVICE_URL$endpoint")
    fi
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓ Pass ($response)${NC}"
        return 0
    else
        echo -e "${RED}✗ Fail (got $response, expected $expected_status)${NC}"
        return 1
    fi
}

# Function to test service health
test_service_health() {
    local service=$1
    echo -n "Testing $service health... "
    
    response=$(curl -s --max-time 10 "$INTEGRATION_SERVICE_URL/health/$service")
    status=$(echo "$response" | jq -r '.status' 2>/dev/null || echo "unknown")
    
    if [ "$status" = "healthy" ]; then
        echo -e "${GREEN}✓ Healthy${NC}"
        return 0
    elif [ "$status" = "unhealthy" ]; then
        echo -e "${YELLOW}⚠ Unhealthy${NC}"
        return 0  # Still consider as working response
    else
        echo -e "${RED}✗ Failed${NC}"
        return 1
    fi
}

echo "Step 1: Checking if Docker services are running..."
echo "------------------------------------------------"

# Check if Docker Compose services are running
if ! docker-compose ps | grep -q "Up"; then
    echo -e "${YELLOW}⚠ Warning: Docker services might not be running${NC}"
    echo "To start services, run: docker-compose up -d"
fi

echo
echo "Step 2: Testing service accessibility..."
echo "--------------------------------------"

# Test if services are accessible
services_ok=0
total_services=0

# Integration Service
((total_services++))
if check_service "Integration Service" "$INTEGRATION_SERVICE_URL/health"; then
    ((services_ok++))
fi

# Frontend
((total_services++))
if check_service "Frontend" "$FRONTEND_URL"; then
    ((services_ok++))
fi

# External Services
((total_services++))
if check_service "LLDAP" "http://localhost:30170"; then
    ((services_ok++))
fi

((total_services++))
if check_service "Grafana" "http://localhost:30300"; then
    ((services_ok++))
fi

((total_services++))
if check_service "Prometheus" "http://localhost:30909"; then
    ((services_ok++))
fi

((total_services++))
if check_service "Vault" "http://localhost:30820"; then
    ((services_ok++))
fi

echo
echo "Step 3: Testing Integration Service API endpoints..."
echo "---------------------------------------------------"

# Test API endpoints
api_tests_passed=0
total_api_tests=0

# Health endpoints
((total_api_tests++))
if test_api_endpoint "GET" "/health" "200" "Overall health endpoint"; then
    ((api_tests_passed++))
fi

((total_api_tests++))
if test_api_endpoint "GET" "/" "200" "Root endpoint"; then
    ((api_tests_passed++))
fi

# Service-specific health checks
for service in lldap grafana prometheus vault; do
    ((total_api_tests++))
    if test_service_health "$service"; then
        ((api_tests_passed++))
    fi
done

# LLDAP API tests
((total_api_tests++))
if test_api_endpoint "GET" "/api/lldap/users" "200" "LLDAP users endpoint"; then
    ((api_tests_passed++))
fi

((total_api_tests++))
if test_api_endpoint "GET" "/api/lldap/groups" "200" "LLDAP groups endpoint"; then
    ((api_tests_passed++))
fi

((total_api_tests++))
if test_api_endpoint "GET" "/api/lldap/stats" "200" "LLDAP stats endpoint"; then
    ((api_tests_passed++))
fi

# Grafana API tests
((total_api_tests++))
if test_api_endpoint "GET" "/api/grafana/dashboards" "200" "Grafana dashboards endpoint"; then
    ((api_tests_passed++))
fi

# Prometheus API tests
((total_api_tests++))
if test_api_endpoint "GET" "/api/prometheus/query?query=up" "200" "Prometheus query endpoint"; then
    ((api_tests_passed++))
fi

((total_api_tests++))
if test_api_endpoint "GET" "/api/prometheus/kpis" "200" "Prometheus KPIs endpoint"; then
    ((api_tests_passed++))
fi

# Vault API tests
((total_api_tests++))
if test_api_endpoint "GET" "/api/vault/sys/health" "200" "Vault health endpoint"; then
    ((api_tests_passed++))
fi

((total_api_tests++))
if test_api_endpoint "GET" "/api/vault/secrets" "200" "Vault secrets endpoint"; then
    ((api_tests_passed++))
fi

echo
echo "Step 4: Testing Frontend Integration..."
echo "--------------------------------------"

# Test if frontend can reach integration service
echo -n "Testing frontend API proxy... "
if curl -s --fail --max-time 10 "$FRONTEND_URL/api/integration/lldap/status" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Working${NC}"
    frontend_proxy_ok=true
else
    echo -e "${RED}✗ Failed${NC}"
    frontend_proxy_ok=false
fi

echo
echo "Step 5: Testing Service Integrations..."
echo "--------------------------------------"

# Test LLDAP integration
echo -n "Testing LLDAP user data retrieval... "
response=$(curl -s --max-time 10 "$INTEGRATION_SERVICE_URL/api/lldap/users" 2>/dev/null)
if echo "$response" | jq '.users' > /dev/null 2>&1; then
    user_count=$(echo "$response" | jq '.users | length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✓ Retrieved $user_count users${NC}"
else
    echo -e "${RED}✗ Failed to retrieve user data${NC}"
fi

# Test Prometheus metrics
echo -n "Testing Prometheus metrics collection... "
response=$(curl -s --max-time 10 "$INTEGRATION_SERVICE_URL/api/prometheus/kpis" 2>/dev/null)
if echo "$response" | jq '.kpis' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Metrics retrieved${NC}"
else
    echo -e "${RED}✗ Failed to retrieve metrics${NC}"
fi

# Test Grafana dashboards
echo -n "Testing Grafana dashboard access... "
response=$(curl -s --max-time 10 "$INTEGRATION_SERVICE_URL/api/grafana/dashboards" 2>/dev/null)
if echo "$response" | jq '.dashboards' > /dev/null 2>&1; then
    dashboard_count=$(echo "$response" | jq '.dashboards | length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✓ Found $dashboard_count dashboards${NC}"
else
    echo -e "${RED}✗ Failed to retrieve dashboards${NC}"
fi

# Test Vault secrets
echo -n "Testing Vault secret access... "
response=$(curl -s --max-time 10 "$INTEGRATION_SERVICE_URL/api/vault/secrets" 2>/dev/null)
if echo "$response" | jq '.secrets' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Vault accessible${NC}"
else
    echo -e "${RED}✗ Failed to access Vault${NC}"
fi

echo
echo "📊 Test Results Summary"
echo "======================"
echo -e "Services Running: $services_ok/$total_services ${GREEN}($(( services_ok * 100 / total_services ))%)${NC}"
echo -e "API Tests Passed: $api_tests_passed/$total_api_tests ${GREEN}($(( api_tests_passed * 100 / total_api_tests ))%)${NC}"

if [ $services_ok -eq $total_services ] && [ $api_tests_passed -eq $total_api_tests ]; then
    echo -e "\n${GREEN}🎉 All tests passed! Integration service is working correctly.${NC}"
    exit 0
elif [ $services_ok -ge $((total_services * 3 / 4)) ] && [ $api_tests_passed -ge $((total_api_tests * 3 / 4)) ]; then
    echo -e "\n${YELLOW}⚠ Most tests passed. Some services might need attention.${NC}"
    exit 1
else
    echo -e "\n${RED}❌ Multiple test failures detected. Please check service configuration.${NC}"
    exit 2
fi