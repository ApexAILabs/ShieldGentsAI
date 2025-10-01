#!/bin/bash

echo "🛡️  ShieldGents Dashboard Launcher"
echo "=================================="
echo ""
echo "Choose a dashboard to run:"
echo ""
echo "1) Interactive Demo (with test interface)"
echo "2) Basic Dashboard"
echo "3) Exit"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "Starting Interactive Demo Dashboard..."
        echo "This includes a test agent interface in the sidebar."
        echo ""
        streamlit run examples/dashboard_with_agent.py
        ;;
    2)
        echo ""
        echo "Starting Basic Dashboard..."
        echo "Click 'Generate Demo Events' to populate with data."
        echo ""
        streamlit run examples/run_dashboard.py
        ;;
    3)
        echo "Goodbye! 👋"
        exit 0
        ;;
    *)
        echo "Invalid choice. Please run again."
        exit 1
        ;;
esac
