"""
Setup script to initialize scan profiles in the database
"""
import asyncio
import json
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from models import ScanProfile, ScanTool, Base
from scan_profiles import SCAN_PROFILES
from database import DATABASE_URL

async def setup_scan_profiles():
    """Initialize scan profiles in the database"""
    print("🚀 Setting up scan profiles in database...")
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with async_session() as session:
        # Clear existing profiles
        await session.execute("DELETE FROM scan_profiles")
        await session.commit()
        
        profile_count = 0
        
        for tool_name, profiles in SCAN_PROFILES.items():
            for profile_name, profile_config in profiles.items():
                try:
                    # Create ScanProfile record
                    scan_profile = ScanProfile(
                        name=f"{tool_name}_{profile_name}",
                        tool=ScanTool(tool_name),
                        description=profile_config["description"],
                        command_template=profile_config["command_template"],
                        default_options=profile_config["default_options"],
                        timeout_seconds=profile_config["timeout_seconds"],
                        is_active=True,
                        is_default=(profile_name == "tcp_syn_scan" and tool_name == "nmap")
                    )
                    
                    session.add(scan_profile)
                    profile_count += 1
                    print(f"  ✅ Added {tool_name.upper()} - {profile_config['name']}")
                    
                except Exception as e:
                    print(f"  ❌ Failed to add {tool_name} - {profile_name}: {e}")
        
        await session.commit()
        print(f"\n🎉 Successfully added {profile_count} scan profiles to database!")
    
    await engine.dispose()

async def verify_profiles():
    """Verify that profiles were created correctly"""
    print("\n🔍 Verifying scan profiles...")
    
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        from sqlalchemy import select, func
        
        # Count total profiles
        result = await session.execute(select(func.count(ScanProfile.id)))
        total_count = result.scalar()
        
        # Count by tool
        result = await session.execute(
            select(ScanProfile.tool, func.count(ScanProfile.id))
            .group_by(ScanProfile.tool)
        )
        tool_counts = dict(result.fetchall())
        
        print(f"📊 Total profiles: {total_count}")
        for tool, count in tool_counts.items():
            print(f"  {tool.upper()}: {count} profiles")
        
        # Show active profiles
        result = await session.execute(
            select(ScanProfile).where(ScanProfile.is_active == True)
        )
        active_profiles = result.scalars().all()
        
        print(f"\n✅ Active profiles ({len(active_profiles)}):")
        for profile in active_profiles:
            default_marker = " (DEFAULT)" if profile.is_default else ""
            print(f"  • {profile.tool.upper()}: {profile.name}{default_marker}")
    
    await engine.dispose()

async def main():
    """Main setup function"""
    print("🔧 SecDash Scan Profiles Setup")
    print("=" * 50)
    
    try:
        await setup_scan_profiles()
        await verify_profiles()
        print("\n🎯 Setup completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
