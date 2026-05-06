from enum import Enum
# time_periods.py

class TimePeriod(Enum):
    """
    Enum representing different time periods that can be used to filter data.

    Usage:
    - `TimePeriod.PREVIOUS_HOUR` represents the hour before the current hour.
    - `TimePeriod.CURRENT_HOUR` represents the current hour.
    - `TimePeriod.NEXT_HOUR` represents the hour after the current hour.
    - `TimePeriod.YESTERDAY` represents the previous day.
    - `TimePeriod.TODAY` represents the current day.
    - `TimePeriod.TOMORROW` represents the next day.
    - `TimePeriod.UPCOMING` represents all future hours.
    - `TimePeriod.BEFORE_6AM` represents all hours before 6 am of the current day.
    - `TimePeriod.AFTER_6AM` represents all hours after 6 am of the current day.
    - `TimePeriod.TOMORROW_BEFORE_6AM` represents all hours before 6 am of the next day.
    - `TimePeriod.TOMORROW_AFTER_6AM` represents all hours after 6 am of the next day.
    - `TimePeriod.PREVIOUS_MONTH` represents all invoices for the previous month.
    - `TimePeriod.CURRENT_MONTH` represents all invoices for the current month.
    - `TimePeriod.NEXT_MONTH` represents all invoices for the next month.
    - `TimePeriod.CURRENT_YEAR` represents all invoices for the current year.
    - `TimePeriod.PREVIOUS_YEAR` represents all invoices for the previous year.
    - `TimePeriod.ALL_TIME` represents all prices or invoices.
    """

    PREVIOUS_HOUR = 'previous_hour'  # The hour before the current hour.
    CURRENT_HOUR = 'current_hour'  # The current hour.
    NEXT_HOUR = 'next_hour'  # The hour after the current hour.
    YESTERDAY = 'yesterday'  # The previous day.
    TODAY = 'today'  # The current day.
    TOMORROW = 'tomorrow'  # The next day.
    UPCOMING = 'upcoming'  # All future hours.
    BEFORE_6AM = 'before_6am'  # All hours before 6am of the current day.
    AFTER_6AM = 'after_6am'  # All hours after 6am of the current day.
    TOMORROW_BEFORE_6AM = 'tomorrow_before_6am'  # All hours before 6am of the next day.
    TOMORROW_AFTER_6AM = 'tomorrow_after_6am'  # All hours after 6am of the next day.
    PREVIOUS_MONTH = 'previous_month'  # All invoices for previous month.
    CURRENT_MONTH = 'current_month'  # All invoices for current month.
    NEXT_MONTH = 'next_month'  # All invoices for previous month.
    CURRENT_YEAR = 'current_year'  # All invoices for current year.
    PREVIOUS_YEAR = 'previous_year'  # All invoices for previous year.
    ALL_TIME = "all_time" # All prices or invoices

    def __str__(self):
        return self.value

    #not in use    
    def get_prices_for_time_period(self, price_data, time_period: 'TimePeriod'):
        if time_period == TimePeriod.TODAY:
            return [hour for hour in price_data if hour.for_today]
        elif time_period == TimePeriod.TOMORROW:
            return [hour for hour in price_data if hour.for_tomorrow]
        else:
            raise ValueError(f"Invalid time period: {time_period}")
