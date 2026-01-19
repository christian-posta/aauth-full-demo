"""
Business policies and logic for the Market Analysis Agent.
Implements core market analysis capabilities for laptop demand forecasting and inventory optimization.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

from tracing_config import add_event, set_attribute


@dataclass
class InventoryItem:
    """Represents a laptop inventory item."""
    model: str
    quantity: int
    specifications: Dict[str, Any]
    last_updated: datetime


@dataclass
class DemandForecast:
    """Represents a demand forecast for laptops."""
    model: str
    projected_demand: int
    timeframe_months: int
    confidence_level: float
    factors: List[str]


@dataclass
class MarketTrend:
    """Represents market trend information."""
    category: str
    trend_direction: str
    impact_level: str
    timeframe: str
    factors: List[str]


@dataclass
class DemandPattern:
    """Represents employee demand patterns by department."""
    department: str
    laptop_preferences: Dict[str, int]
    growth_rate: float
    refresh_cycle_months: int


class MarketAnalysisPolicies:
    """Business policies and logic for market analysis."""
    
    def __init__(self):
        # Default analysis parameters
        self.default_forecast_months = 6
        self.inventory_buffer_months = 3
        self.confidence_threshold = 0.7
        
        # Department laptop preferences (example data)
        self.department_preferences = {
            "engineering": {
                "MacBook Pro": 0.8,
                "MacBook Air": 0.2
            },
            "sales": {
                "MacBook Pro": 0.3,
                "MacBook Air": 0.7
            },
            "marketing": {
                "MacBook Pro": 0.5,
                "MacBook Air": 0.5
            },
            "operations": {
                "MacBook Pro": 0.4,
                "MacBook Air": 0.6
            }
        }
    
    def analyze_inventory_demand(self, 
                               current_inventory: List[InventoryItem],
                               hiring_forecast: Dict[str, int],
                               refresh_cycle_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze current laptop inventory against projected demand.
        
        Args:
            current_inventory: Current laptop inventory levels
            hiring_forecast: Expected new hires by department
            refresh_cycle_data: Information about laptop refresh cycles
            
        Returns:
            Analysis results with gaps and recommendations
        """
        add_event("inventory_demand_analysis_started")
        set_attribute("analysis.inventory_count", len(current_inventory))
        set_attribute("analysis.departments_count", len(hiring_forecast))
        
        analysis = {
            "inventory_gaps": [],
            "inventory_surplus": [],
            "recommendations": [],
            "risk_assessment": "low"
        }
        
        # Calculate total projected demand
        total_demand = self._calculate_total_demand(hiring_forecast, refresh_cycle_data)
        set_attribute("analysis.total_demand", str(total_demand))
        
        # Analyze each laptop model
        for model in ["MacBook Pro", "MacBook Air"]:
            current_stock = self._get_current_stock(current_inventory, model)
            projected_need = total_demand.get(model, 0)
            
            # Apply inventory buffer
            required_stock = projected_need + (projected_need * self.inventory_buffer_months / 12)
            
            if current_stock < required_stock:
                gap = required_stock - current_stock
                analysis["inventory_gaps"].append({
                    "model": model,
                    "current_stock": current_stock,
                    "required_stock": int(required_stock),
                    "gap": int(gap),
                    "priority": "high" if gap > 20 else "medium"
                })
                
                analysis["recommendations"].append(
                    f"Procure {int(gap)} {model} units to meet projected demand"
                )
                
            elif current_stock > required_stock * 1.5:  # 50% surplus threshold
                surplus = current_stock - required_stock
                analysis["inventory_surplus"].append({
                    "model": model,
                    "current_stock": current_stock,
                    "required_stock": int(required_stock),
                    "surplus": int(surplus)
                })
                
                analysis["recommendations"].append(
                    f"Consider reducing {model} procurement - {int(surplus)} units surplus"
                )
        
        # Update risk assessment based on gaps
        if any(gap["priority"] == "high" for gap in analysis["inventory_gaps"]):
            analysis["risk_assessment"] = "high"
        elif analysis["inventory_gaps"]:
            analysis["risk_assessment"] = "medium"
        
        set_attribute("analysis.risk_assessment", analysis["risk_assessment"])
        set_attribute("analysis.gaps_count", len(analysis["inventory_gaps"]))
        set_attribute("analysis.surplus_count", len(analysis["inventory_surplus"]))
        add_event("inventory_demand_analysis_completed")
            
        return analysis
    
    def forecast_market_trends(self, 
                             market_data: Dict[str, Any],
                             time_horizon_months: int = None) -> List[MarketTrend]:
        """
        Forecast laptop market trends and pricing fluctuations.
        
        Args:
            market_data: Market information from external sources
            time_horizon_months: Forecast timeframe
            
        Returns:
            List of market trends with impact assessments
        """
        if time_horizon_months is None:
            time_horizon_months = self.default_forecast_months
            
        trends = []
        
        # Analyze Apple release cycle impact
        apple_release_impact = self._analyze_apple_release_cycle(time_horizon_months)
        if apple_release_impact:
            trends.append(apple_release_impact)
        
        # Analyze seasonal demand patterns
        seasonal_trend = self._analyze_seasonal_patterns(time_horizon_months)
        if seasonal_trend:
            trends.append(seasonal_trend)
        
        # Analyze supply chain risks
        supply_chain_risk = self._analyze_supply_chain_risks(market_data)
        if supply_chain_risk:
            trends.append(supply_chain_risk)
        
        # Analyze pricing trends
        pricing_trend = self._analyze_pricing_trends(market_data, time_horizon_months)
        if pricing_trend:
            trends.append(pricing_trend)
            
        return trends
    
    def model_demand_patterns(self, 
                            department_data: Dict[str, Any],
                            growth_projections: Dict[str, float],
                            historical_usage: Dict[str, Any]) -> Dict[str, DemandPattern]:
        """
        Model laptop demand patterns based on department growth and requirements.
        
        Args:
            department_data: Department information and laptop requirements
            growth_projections: Expected growth rates by department
            historical_usage: Historical laptop usage patterns
            
        Returns:
            Demand patterns by department
        """
        demand_patterns = {}
        
        for dept, data in department_data.items():
            growth_rate = growth_projections.get(dept, 0.0)
            current_headcount = data.get("current_headcount", 0)
            
            # Calculate projected headcount
            projected_headcount = int(current_headcount * (1 + growth_rate))
            
            # Determine laptop mix based on department preferences
            laptop_mix = self._calculate_laptop_mix(dept, projected_headcount)
            
            # Factor in refresh cycles
            refresh_cycle = self._get_refresh_cycle(dept, historical_usage)
            
            demand_patterns[dept] = DemandPattern(
                department=dept,
                laptop_preferences=laptop_mix,
                growth_rate=growth_rate,
                refresh_cycle_months=refresh_cycle
            )
        
        return demand_patterns
    
    def generate_procurement_recommendations(self, 
                                          inventory_analysis: Dict[str, Any],
                                          market_trends: List[MarketTrend],
                                          demand_patterns: Dict[str, DemandPattern]) -> Dict[str, Any]:
        """
        Generate comprehensive procurement recommendations based on analysis.
        
        Args:
            inventory_analysis: Results from inventory demand analysis
            market_trends: Market trend forecasts
            demand_patterns: Employee demand patterns
            
        Returns:
            Procurement recommendations with priorities and timelines
        """
        recommendations = {
            "immediate_actions": [],
            "short_term_planning": [],
            "long_term_strategy": [],
            "risk_mitigation": [],
            "total_estimated_cost": 0
        }
        
        # Process inventory gaps
        for gap in inventory_analysis.get("inventory_gaps", []):
            if gap["priority"] == "high":
                recommendations["immediate_actions"].append({
                    "action": f"Procure {gap['gap']} {gap['model']} units",
                    "priority": "high",
                    "timeline": "2-4 weeks",
                    "estimated_cost": self._estimate_cost(gap["model"], gap["gap"])
                })
            else:
                recommendations["short_term_planning"].append({
                    "action": f"Plan procurement of {gap['gap']} {gap['model']} units",
                    "priority": "medium",
                    "timeline": "1-2 months",
                    "estimated_cost": self._estimate_cost(gap["model"], gap["gap"])
                })
        
        # Consider market trends in recommendations
        for trend in market_trends:
            if trend.impact_level == "high":
                if "price increase" in trend.trend_direction.lower():
                    recommendations["risk_mitigation"].append({
                        "action": "Accelerate procurement to avoid price increases",
                        "reason": trend.factors[0] if trend.factors else "Market trend analysis",
                        "timeline": "Immediate"
                    })
                elif "shortage" in trend.trend_direction.lower():
                    recommendations["risk_mitigation"].append({
                        "action": "Increase safety stock levels",
                        "reason": "Potential supply shortage",
                        "timeline": "1-2 months"
                    })
        
        # Calculate total estimated cost
        for category in ["immediate_actions", "short_term_planning"]:
            for rec in recommendations[category]:
                recommendations["total_estimated_cost"] += rec.get("estimated_cost", 0)
        
        return recommendations
    
    def _calculate_total_demand(self, 
                              hiring_forecast: Dict[str, int], 
                              refresh_cycle_data: Dict[str, Any]) -> Dict[str, int]:
        """Calculate total laptop demand by model."""
        total_demand = {"MacBook Pro": 0, "MacBook Air": 0}
        
        for dept, new_hires in hiring_forecast.items():
            dept_prefs = self.department_preferences.get(dept, {"MacBook Pro": 0.5, "MacBook Air": 0.5})
            
            for model, ratio in dept_prefs.items():
                total_demand[model] += int(new_hires * ratio)
        
        # Add refresh cycle demand
        for model, refresh_count in refresh_cycle_data.get("refresh_needed", {}).items():
            if model in total_demand:
                total_demand[model] += refresh_count
        
        return total_demand
    
    def _get_current_stock(self, inventory: List[InventoryItem], model: str) -> int:
        """Get current stock level for a specific model."""
        for item in inventory:
            if item.model == model:
                return item.quantity
        return 0
    
    def _analyze_apple_release_cycle(self, months: int) -> Optional[MarketTrend]:
        """Analyze impact of Apple's release cycle."""
        # Simplified logic - in real implementation, this would use actual release data
        if months <= 3:
            return MarketTrend(
                category="Product Releases",
                trend_direction="New models expected",
                impact_level="medium",
                timeframe="3 months",
                factors=["Apple typically releases new MacBook models in Q2/Q3"]
            )
        return None
    
    def _analyze_seasonal_patterns(self, months: int) -> Optional[MarketTrend]:
        """Analyze seasonal demand patterns."""
        current_month = datetime.now().month
        
        if 8 <= current_month <= 10:  # Back to school season
            return MarketTrend(
                category="Seasonal Demand",
                trend_direction="Increased demand",
                impact_level="medium",
                timeframe="3-4 months",
                factors=["Back to school season", "Corporate Q4 planning"]
            )
        return None
    
    def _analyze_supply_chain_risks(self, market_data: Dict[str, Any]) -> Optional[MarketTrend]:
        """Analyze supply chain risks."""
        # Simplified - would use real market data
        if market_data.get("supply_chain_issues"):
            return MarketTrend(
                category="Supply Chain",
                trend_direction="Potential shortages",
                impact_level="high",
                timeframe="6 months",
                factors=["Global supply chain disruptions", "Component shortages"]
            )
        return None
    
    def _analyze_pricing_trends(self, market_data: Dict[str, Any], months: int) -> Optional[MarketTrend]:
        """Analyze pricing trends."""
        # Simplified - would use real pricing data
        if market_data.get("price_increases"):
            return MarketTrend(
                category="Pricing",
                trend_direction="Price increases expected",
                impact_level="medium",
                timeframe=f"{months} months",
                factors=["Component cost increases", "Inflation pressure"]
            )
        return None
    
    def _calculate_laptop_mix(self, department: str, headcount: int) -> Dict[str, int]:
        """Calculate laptop mix for a department."""
        prefs = self.department_preferences.get(department, {"MacBook Pro": 0.5, "MacBook Air": 0.5})
        
        mix = {}
        for model, ratio in prefs.items():
            mix[model] = int(headcount * ratio)
        
        return mix
    
    def _get_refresh_cycle(self, department: str, historical_usage: Dict[str, Any]) -> int:
        """Get refresh cycle for a department."""
        # Default refresh cycles by department
        default_cycles = {
            "engineering": 36,  # 3 years
            "sales": 48,        # 4 years
            "marketing": 42,    # 3.5 years
            "operations": 48    # 4 years
        }
        
        return historical_usage.get(department, {}).get("refresh_cycle_months", 
                                                      default_cycles.get(department, 48))
    
    def _estimate_cost(self, model: str, quantity: int) -> float:
        """Estimate cost for laptop procurement."""
        # Simplified cost estimates
        unit_costs = {
            "MacBook Pro": 2500,
            "MacBook Air": 1500
        }
        
        unit_cost = unit_costs.get(model, 2000)
        return unit_cost * quantity


# Global instance for use by the agent
market_analysis_policies = MarketAnalysisPolicies()
