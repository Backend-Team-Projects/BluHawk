from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated

from django.utils.timezone import now

from datetime import  timedelta


from django.conf import settings
from django.template.loader import render_to_string

import os
from dotenv import load_dotenv

from BluHawk.AsyncDataProcessing import AsyncDataProcessing
from BluHawk.utils import *
from BluHawk.config import TRACKED_ENDPOINTS

from BluHawk.models import *


class getUsage(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

            for i in TRACKED_ENDPOINTS:
                if not UserRequestLog.objects.filter(endpoint=i, user= user).exists():
                    UserRequestLog.objects.create(user=user, endpoint=i, count=0)

            logs = UserRequestLog.objects.filter(user=user).values('endpoint', 'count', 'last_request')
            return Response({"logs": list(logs)}, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            return log_exception(e)

from usage.models import RequestLogs
class GetPaginatedRequestLogs(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

            logs_queryset = RequestLogs.objects.filter(user=user).order_by('-created_at').values(
                'api_name', 'group', 'status_code', 'created_at'
            )

            page = int(request.query_params.get('page', 1))
            page_size = 20
            start = (page - 1) * page_size
            end = start + page_size
            paginated_logs = list(logs_queryset[start:end])

            total_logs = logs_queryset.count()
            total_pages = (total_logs // page_size) + (1 if total_logs % page_size > 0 else 0)

            return Response({
                "logs": paginated_logs,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "total_logs": total_logs
            }, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetTimeFramedLogs(APIView):
                permission_classes = [IsAuthenticated]

                def get(self, request, *args, **kwargs):
                    try:
                        user = request.user
                        if not user:
                            return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

                        from_date = request.query_params.get('from')
                        to_date = request.query_params.get('to')

                        if not from_date or not to_date:
                            return Response({"error": "Both 'from' and 'to' dates are required"}, 
                                          status=status.HTTP_400_BAD_REQUEST)

                        try:
                            from_date = datetime.strptime(from_date, "%Y-%m-%d").date()
                            to_date = datetime.strptime(to_date, "%Y-%m-%d").date()
                        except ValueError:
                            return Response({"error": "Invalid date format. Use YYYY-MM-DD"}, 
                                          status=status.HTTP_400_BAD_REQUEST)

                        date_diff = (to_date - from_date).days
                        if date_diff > 365:
                            return Response({"error": "Time frame cannot exceed one year"}, 
                                          status=status.HTTP_400_BAD_REQUEST)

                        logs = RequestLogs.objects.filter(
                            user=user,
                            created_at__date__gte=from_date,
                            created_at__date__lte=to_date
                        ).order_by('-created_at').values(
                            'api_name', 'group', 'status_code', 'created_at'
                        )

                        return Response({"logs": list(logs)}, status=status.HTTP_200_OK)

                    except Exception as e:
                        log_exception(e)
                        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class GetUsageStats(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        from django.utils.timezone import now
        from datetime import timedelta, datetime
        from django.db.models import Count
        from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
        import collections
        
        try:
            user = request.user
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

            time_frame = request.query_params.get('time_frame', 'this_week').lower()  # Default to this_week
            from_date = request.query_params.get('from')
            to_date = request.query_params.get('to')

            today = now().date()
            start_date = None
            end_date = today + timedelta(days=1)  # Include today
            group_by = 'day'  # Default grouping

            # Determine start_date, end_date and group_by based on time_frame
            if time_frame == 'today':
                start_date = today
                group_by = 'day'  # Show hours within today
            elif time_frame == 'yesterday':
                start_date = today - timedelta(days=1)
                end_date = today
                group_by = 'day'  # Show hours within yesterday
            elif time_frame == 'this_week':
                start_date = today - timedelta(days=today.weekday())  # Monday
                group_by = 'day_of_week'  # Special case for showing Monday-Sunday
            elif time_frame == 'this_month':
                start_date = today.replace(day=1)
                group_by = 'week'  # Show weeks of the month
            elif time_frame == 'this_year':
                start_date = today.replace(month=1, day=1)
                group_by = 'month'  # Show months of the year
            elif time_frame == 'custom':
                if not from_date or not to_date:
                    return Response({"error": "Custom time frame requires 'from' and 'to' parameters."},
                                    status=status.HTTP_400_BAD_REQUEST)
                try:
                    start_date = datetime.strptime(from_date, "%Y-%m-%d").date()
                    end_date = datetime.strptime(to_date, "%Y-%m-%d").date() + timedelta(days=1)
                    days_diff = (end_date - start_date).days
                    
                    # Determine grouping based on time span
                    if days_diff <= 14:  # Up to 2 weeks
                        group_by = 'day'
                    elif days_diff <= 60:  # Up to ~2 months
                        group_by = 'week'
                    else:
                        group_by = 'month'
                except ValueError:
                    return Response({"error": "Invalid date format. Use YYYY-MM-DD."},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "Invalid time frame."}, status=status.HTTP_400_BAD_REQUEST)

            logs = RequestLogs.objects.filter(
                user=user,
                created_at__date__gte=start_date,
                created_at__date__lt=end_date
            )

            # === Pie chart data (group distribution) ===
            grouped = logs.values('group').annotate(count=Count('id'))
            total = sum(entry['count'] for entry in grouped)
            pie_chart_data = {
                entry['group']: round((entry['count'] / total) * 100, 2)
                for entry in grouped
            } if total else {}

            # === Bar chart data (API usage trend) ===
            bar_chart_data = []

            if group_by == 'day_of_week':
                # Special case: Show Monday-Sunday with counts for each day
                day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                day_counts = {day: 0 for day in day_names}
                
                # Get counts per day
                day_grouped = logs.annotate(
                    day_of_week=TruncDay('created_at')
                ).values('day_of_week').annotate(count=Count('id')).order_by('day_of_week')
                
                # Map counts to day names
                for entry in day_grouped:
                    day_name = entry['day_of_week'].strftime('%A')
                    day_counts[day_name] = entry['count']
                
                bar_chart_data = [{"period": day, "count": count} for day, count in day_counts.items()]
            
            elif group_by == 'day':
                # Group by day and ensure all days are included
                all_days = collections.OrderedDict()
                current_day = start_date
                while current_day < end_date:
                    all_days[current_day.strftime("%Y-%m-%d")] = 0
                    current_day += timedelta(days=1)
                
                # Get actual counts
                day_grouped = logs.annotate(
                    day=TruncDay('created_at')
                ).values('day').annotate(count=Count('id')).order_by('day')
                
                # Update counts
                for entry in day_grouped:
                    day_str = entry['day'].strftime("%Y-%m-%d")
                    all_days[day_str] = entry['count']
                
                bar_chart_data = [{"period": day, "count": count} for day, count in all_days.items()]
            
            elif group_by == 'week':
                # Group by week and ensure all weeks are included
                all_weeks = collections.OrderedDict()
                current_week_start = start_date - timedelta(days=start_date.weekday())  # Previous Monday
                
                while current_week_start < end_date:
                    week_label = current_week_start.strftime("Week of %Y-%m-%d")
                    all_weeks[week_label] = 0
                    current_week_start += timedelta(weeks=1)
                
                # Get actual counts
                week_grouped = logs.annotate(
                    week=TruncWeek('created_at')
                ).values('week').annotate(count=Count('id')).order_by('week')
                
                # Update counts
                for entry in week_grouped:
                    week_start = entry['week'].date() - timedelta(days=entry['week'].date().weekday())
                    week_label = week_start.strftime("Week of %Y-%m-%d")
                    all_weeks[week_label] = entry['count']
                
                bar_chart_data = [{"period": week, "count": count} for week, count in all_weeks.items()]
            
            elif group_by == 'month':
                # Group by month and ensure all months are included
                all_months = collections.OrderedDict()
                current_month = start_date.replace(day=1)
                
                while current_month < end_date:
                    month_label = current_month.strftime("%Y-%m")
                    all_months[month_label] = 0
                    # Move to next month
                    if current_month.month == 12:
                        current_month = current_month.replace(year=current_month.year+1, month=1)
                    else:
                        current_month = current_month.replace(month=current_month.month+1)
                
                # Get actual counts
                month_grouped = logs.annotate(
                    month=TruncMonth('created_at')
                ).values('month').annotate(count=Count('id')).order_by('month')
                
                # Update counts
                for entry in month_grouped:
                    month_label = entry['month'].strftime("%Y-%m")
                    all_months[month_label] = entry['count']
                
                bar_chart_data = [{"period": month, "count": count} for month, count in all_months.items()]

            return Response({
                "pie_chart_data": pie_chart_data,
                "bar_chart_data": bar_chart_data,
                "time_frame": time_frame,
                "grouping": group_by
            }, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

from session_management.models import Scanlog
from django.db.models import Q

class GetPaginatedScanLogs(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            if not user:
                return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

            # Base queryset with sorting at database level
            logs_queryset = Scanlog.objects.filter(user=user).order_by('-timestamp')

            # Apply time filter or custom range
            time_filter = request.query_params.get('time_filter', 'alltime')
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')

            now = datetime.now()

            if start_date or end_date:
                if not (start_date and end_date):
                    return Response({"error": "Both start_date and end_date are required for custom range."},
                                    status=status.HTTP_400_BAD_REQUEST)
                try:
                    start_time = datetime.strptime(start_date, '%Y-%m-%d').replace(hour=0, minute=0, second=0, microsecond=0)
                    end_time = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59, microsecond=999999)
                    logs_queryset = logs_queryset.filter(timestamp__range=[start_time, end_time])
                except ValueError:
                    return Response({"error": "Invalid date format. Use YYYY-MM-DD for both start_date and end_date."},
                                    status=status.HTTP_400_BAD_REQUEST)
            elif time_filter:
                if time_filter == 'today':
                    start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
                    logs_queryset = logs_queryset.filter(timestamp__gte=start_time)
                elif time_filter == 'yesterday':
                    start_time = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                    end_time = start_time + timedelta(days=1)
                    logs_queryset = logs_queryset.filter(timestamp__range=[start_time, end_time])
                elif time_filter == 'this_week':
                    start_time = now - timedelta(days=now.weekday())
                    start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
                    logs_queryset = logs_queryset.filter(timestamp__gte=start_time)
                elif time_filter == 'this_month':
                    start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    logs_queryset = logs_queryset.filter(timestamp__gte=start_time)
                elif time_filter == 'this_year':
                    start_time = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
                    logs_queryset = logs_queryset.filter(timestamp__gte=start_time)
                elif time_filter == 'alltime':
                    pass  # No filter

            # Apply role and user filter on the time-filtered data
            role_user_filter = request.query_params.get('role_user', None)
            if role_user_filter:
                logs_queryset = logs_queryset.filter(
                    Q(role__icontains=role_user_filter) |
                    Q(user__username__icontains=role_user_filter)
                )

            # Select specific fields
            logs_queryset = logs_queryset.values(
                'scan_name',
                'user__username',
                'role',
                'timestamp',
                'json_data'
            )

            # Pagination
            try:
                page = int(request.query_params.get('page', 1))
            except ValueError:
                return Response({"error": "Invalid page number."}, status=status.HTTP_400_BAD_REQUEST)

            page_size = 20
            max_pages = 50

            if page < 1:
                page = 1
            elif page > max_pages:
                page = max_pages

            start = (page - 1) * page_size
            end = start + page_size
            paginated_logs = list(logs_queryset[start:end])

            total_logs = logs_queryset.count()
            total_pages = min((total_logs // page_size) + (1 if total_logs % page_size > 0 else 0), max_pages)

            return Response({
                "logs": paginated_logs,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "total_logs": total_logs
            }, status=status.HTTP_200_OK)

        except Exception as e:
            log_exception(e)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)